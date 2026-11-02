"""Shared bounded transport for exact-email public-source lookups."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone

from neesha.adapters.base import AdapterError, FactDraft, RawResult
from neesha.collectors.network import _default_context

MAX_BYTES = 1024 * 1024


def normalize_email(value: str) -> str:
    """Preserve local-part spelling and aliases; canonicalize only the domain."""
    if not isinstance(value, str):
        raise AdapterError('Enter a valid email address')
    value = value.strip()
    if value.count('@') != 1 or len(value) > 254:
        raise AdapterError('Enter a valid email address')
    local, domain = value.rsplit('@', 1)
    try:
        domain = domain.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise AdapterError('Enter a valid email address') from None
    if (not 1 <= len(local) <= 64 or local.startswith('.') or local.endswith('.') or '..' in local
            or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local)
            or len(domain.split('.')) < 2 or any(
                not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                for label in domain.split('.'))):
        raise AdapterError('Enter a valid email address')
    return local + '@' + domain


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def get_json(url: str, *, headers=None, source: str, allow_not_found=False):
    request = urllib.request.Request(url, headers={
        'User-Agent': 'NEESHA/0.1 public-source research', 'Accept': 'application/json', **(headers or {})})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                            urllib.request.HTTPSHandler(context=_default_context()))
        with opener.open(request, timeout=15) as response:
            body = response.read(MAX_BYTES + 1)
            status = response.status
        if len(body) > MAX_BYTES:
            raise AdapterError(f'{source} response exceeds the public-data size limit')
        return json.loads(body), status
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and allow_not_found:
            return None, 404
        if exc.code in (403, 429):
            raise AdapterError(f'{source} access or rate limit prevented public collection') from None
        raise AdapterError(f'{source} public request failed') from None
    except AdapterError:
        raise
    except Exception:
        raise AdapterError(f'{source} public request failed') from None


def result(payload, reference, status=200):
    """Persist only the adapter's allowlisted public metadata, never raw bodies."""
    return RawResult(payload=json.dumps(payload, sort_keys=True).encode(),
                     request_url=reference.url, origin_url=reference.origin_url,
                     http_status=status, content_type='application/json',
                     collected_at=datetime.now(timezone.utc))


def fact(email: str, attribute: str, value: str, *, is_inference=False, value_type='str'):
    return FactDraft(attribute=attribute, value=value, entity_kind='email',
                     entity_name=email, identity_key='email:' + email,
                     sensitivity='personal', is_inference=is_inference, value_type=value_type)


def stored_json(raw):
    if len(raw.payload) > MAX_BYTES:
        raise AdapterError('Public metadata exceeds the size limit')
    try:
        data = json.loads(raw.payload)
    except (ValueError, UnicodeError):
        raise AdapterError('Invalid public metadata response') from None
    if not isinstance(data, dict):
        raise AdapterError('Invalid public metadata response')
    return data
