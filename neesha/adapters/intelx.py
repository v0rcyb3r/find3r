"""Opt-in Intelligence X search metadata; never retrieves or persists files.

Verified contract: official IntelligenceX/SDK Python/intelx/intelxapi.py.
Only allowlisted aggregate counts leave the in-memory provider response.
RawResult and the cache therefore never contain record titles, selectors,
credentials, file contents, names, email addresses, or provider search IDs.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import ClassVar
from uuid import UUID

from neesha.adapters.base import AdapterError, BaseAdapter, Cost, FactDraft, RawResult, Reference, Request
from neesha.collectors.network import _default_context

API_ROOT = 'https://2.intelx.io'
API_DOCUMENTATION = 'https://github.com/IntelligenceX/SDK/blob/master/Python/intelx/intelxapi.py'
_RATE_LOCK = threading.Lock()
_LAST_CALL = 0.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _domain(value: str) -> str:
    value = value.strip().lower().rstrip('.')
    if len(value) > 253 or len(value.split('.')) < 2 or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
        for part in value.split('.')
    ):
        raise AdapterError('Intelligence X metadata search requires a company domain')
    return value


class IntelXAdapter(BaseAdapter):
    name: ClassVar[str] = 'intelx'
    tier: ClassVar[str] = 'C'
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = 'third_party_passive'
    source_type: ClassVar[str] = 'commercial_api'
    description: ClassVar[str] = 'Intelligence X company search aggregates; no file or record export'
    produces: ClassVar[frozenset[str]] = frozenset({'intelx.search'})
    accepts: ClassVar[frozenset[str]] = frozenset({'company', 'domain'})
    requires_techniques: ClassVar[frozenset[str]] = frozenset({'breach_metadata'})
    retention_days: ClassVar[int] = 7
    max_results: ClassVar[int] = 100
    max_polls: ClassVar[int] = 3
    max_response_bytes: ClassVar[int] = 1024 * 1024
    timeout: ClassVar[int] = 10

    def estimate_cost(self, request: Request) -> Cost:
        raw_price = os.environ.get('INTELX_ESTIMATED_USD_PER_SEARCH', '0.05')
        try:
            amount = Decimal(raw_price)
        except InvalidOperation:
            amount = Decimal('NaN')
        if not amount.is_finite() or not Decimal('0.0001') <= amount <= Decimal('1000000'):
            raise AdapterError('Configure a positive INTELX_ESTIMATED_USD_PER_SEARCH covering the complete bounded search before collection')
        return Cost(usd=float(amount), basis='per_call')

    def _key(self) -> str:
        key = os.environ.get('INTELX_API_KEY') or os.environ.get('INTELX_KEY')
        if not key:
            raise AdapterError('Intelligence X API key is not configured')
        return key

    def availability(self) -> dict:
        try:
            self._key()
            self.estimate_cost(Request('domain', 'example.com'))
        except AdapterError as exc:
            return {'available': False, 'reason': str(exc)}
        return {'available': True, 'reason': 'Metadata-only; requires client engagement, breach_metadata permission, analyst approval, and budget.'}

    def search(self, request: Request) -> list[Reference]:
        domain = _domain(request.value)
        return [Reference(url=API_ROOT + '/intelligent/search', origin_url='https://intelx.io/', label=domain)]

    def _request_json(self, path: str, *, payload=None, params=None) -> dict:
        global _LAST_CALL
        # All API calls, including polling and termination, share the provider's
        # documented 1 request/second ceiling across adapter instances.
        with _RATE_LOCK:
            delay = 1.0 - (time.monotonic() - _LAST_CALL)
            if delay > 0:
                time.sleep(delay)
            _LAST_CALL = time.monotonic()
            url = API_ROOT + path
            if params:
                url += '?' + urllib.parse.urlencode(params)
            headers = {'X-Key': self._key(), 'User-Agent': 'NEESHA/0.1', 'Accept': 'application/json'}
            if payload is not None:
                headers['Content-Type'] = 'application/json'
            request = urllib.request.Request(
                url, data=json.dumps(payload).encode() if payload is not None else None,
                headers=headers, method='POST' if payload is not None else 'GET',
            )
            try:
                opener = urllib.request.build_opener(
                    _NoRedirect(), urllib.request.HTTPSHandler(context=_default_context()))
                with opener.open(request, timeout=self.timeout) as response:
                    body = response.read(self.max_response_bytes + 1)
                if len(body) > self.max_response_bytes:
                    raise AdapterError('Intelligence X response exceeds the metadata size limit')
                result = json.loads(body)
                if not isinstance(result, dict):
                    raise AdapterError('Intelligence X returned an unexpected response shape')
                return result
            except AdapterError:
                raise
            except Exception:
                # Provider bodies, URLs, and credential-bearing exceptions are
                # deliberately excluded from errors and exception chaining.
                raise AdapterError('Intelligence X metadata request failed') from None

    def fetch(self, reference: Reference) -> RawResult:
        domain = _domain(reference.label)
        self._key()
        self.estimate_cost(Request('domain', domain))
        search_id = None
        categories = {'leaks': 0, 'pastes': 0, 'darknet': 0, 'other': 0}
        sampled = 0
        partial = True
        try:
            started = self._request_json('/intelligent/search', payload={
                'term': domain, 'buckets': [], 'lookuplevel': 0,
                'maxresults': self.max_results, 'timeout': 5,
                'datefrom': '', 'dateto': '', 'sort': 4, 'media': 0, 'terminate': [],
            })
            candidate = started.get('id')
            if not isinstance(candidate, str):
                raise AdapterError('Intelligence X did not return a valid search identifier')
            try:
                search_id = str(UUID(candidate))
            except ValueError:
                raise AdapterError('Intelligence X did not return a valid search identifier') from None
            for _ in range(self.max_polls):
                response = self._request_json('/intelligent/search/result', params={
                    'id': search_id, 'limit': self.max_results - sampled,
                })
                status, records = response.get('status'), response.get('records', [])
                if type(status) is not int or status not in (0, 1, 3) or not isinstance(records, list):
                    raise AdapterError('Intelligence X returned invalid search metadata')
                for record in records[:self.max_results - sampled]:
                    if not isinstance(record, dict):
                        continue
                    bucket = record.get('bucket')
                    category = bucket.split('.', 1)[0] if isinstance(bucket, str) else 'other'
                    if category not in categories:
                        category = 'other'
                    categories[category] += 1
                    sampled += 1
                if status == 1:
                    partial = False
                    break
                if sampled >= self.max_results:
                    break
        finally:
            # Never fetch previews, selectors, exports, or original files.
            if search_id is not None:
                try:
                    self._request_json('/intelligent/search/terminate', params={'id': search_id})
                except AdapterError:
                    pass
        safe = {'domain': domain, 'sample_count': sampled,
                'partial': partial, 'category_counts': categories}
        return RawResult(payload=json.dumps(safe, sort_keys=True).encode(),
                         request_url=API_ROOT + '/intelligent/search', origin_url='https://intelx.io/',
                         content_type='application/json', collected_at=datetime.now(timezone.utc))

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        try:
            data = json.loads(raw.payload)
        except (ValueError, UnicodeError):
            raise AdapterError('Invalid sanitized Intelligence X metadata') from None
        domain = _domain(request.value)
        if not isinstance(data, dict) or data.get('domain') != domain:
            raise AdapterError('Intelligence X metadata does not match the company domain')
        count, partial, categories = data.get('sample_count'), data.get('partial'), data.get('category_counts')
        if (type(count) is not int or not 0 <= count <= self.max_results
                or type(partial) is not bool or not isinstance(categories, dict)
                or set(categories) != {'leaks', 'pastes', 'darknet', 'other'}
                or any(type(n) is not int or n < 0 for n in categories.values())
                or sum(categories.values()) != count):
            raise AdapterError('Invalid sanitized Intelligence X metadata')
        facts = [FactDraft(attribute='intelx.search.sample_count', value=str(count),
                           entity_kind='company', entity_name=domain, value_type='int'),
                 FactDraft(attribute='intelx.search.is_partial', value=str(partial).lower(),
                           entity_kind='company', entity_name=domain, value_type='bool')]
        facts += [FactDraft(attribute='intelx.search.category.' + category, value=str(number),
                            entity_kind='company', entity_name=domain, value_type='int')
                  for category, number in sorted(categories.items())]
        return facts
