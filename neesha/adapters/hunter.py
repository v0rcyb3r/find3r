"""Hunter business-email search with bounded, result-priced collection.

The current official API supports X-API-KEY authentication. Keys therefore
never appear in request URLs or provenance. Domain Search charges depend on
returned emails; the operator must configure a conservative per-search USD
estimate covering the configured result cap. No fixed provider price is assumed.

Only addresses matching the requested company domain become person facts.
Professional-role facts retain the stable email identity key.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import urllib.parse
from typing import ClassVar, Optional

from neesha.adapters.base import (
    AdapterError,
    BaseAdapter,
    Cost,
    FactDraft,
    RawResult,
    Reference,
    Request,
)
from neesha.collectors.network import _default_context

API_KEY_ENV = "HUNTER_API_KEY"

PRICE_ENV = 'HUNTER_ESTIMATED_USD_PER_SEARCH'
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def http_get(url: str, headers=None, timeout=30) -> str:
    """Bound response size and refuse credential-forwarding redirects."""
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=_default_context()))
    request = urllib.request.Request(url, headers={'User-Agent': 'NEESHA/0.1', **(headers or {})})
    with opener.open(request, timeout=timeout) as response:
        payload = response.read(MAX_PAYLOAD_BYTES + 1)
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise AdapterError('Hunter response exceeds the collection size limit')
    return payload.decode('utf-8', errors='replace')


def _domain(value: str) -> str:
    domain = value.strip().lower().rstrip('.')
    if len(domain) > 253 or len(domain.split('.')) < 2 or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
        for label in domain.split('.')
    ):
        raise AdapterError('Hunter requires a valid company domain')
    return domain


# Short on purpose: personal data we control, so we keep it only as long as a
# briefing cycle needs it.
RETENTION_DAYS = 30


class HunterAdapter(BaseAdapter):
    name: ClassVar[str] = "hunter"
    tier: ClassVar[str] = "B"
    collection_mode: ClassVar[str] = "third_party_passive"
    description: ClassVar[str] = "Hunter.io business email discovery (metered)"
    source_type: ClassVar[str] = "commercial_api"
    produces: ClassVar[frozenset[str]] = frozenset(
        {"person.business_email", "person.role", "person.seniority", "email.pattern"}
    )
    accepts: ClassVar[frozenset[str]] = frozenset({"company", "domain"})
    retention_days: ClassVar[int] = RETENTION_DAYS

    max_people: ClassVar[int] = 10

    def __init__(self, api_key: Optional[str] = None, *, max_people: int = 10):
        if type(max_people) is not int or not 1 <= max_people <= 100:
            raise AdapterError('Hunter result cap must be between 1 and 100')
        self._api_key = api_key
        self.max_people = max_people

    # ---- cost ------------------------------------------------------------

    def estimate_cost(self, request: Request) -> Cost:
        self._limit(request)
        try:
            amount = Decimal(os.environ.get(PRICE_ENV, ''))
        except InvalidOperation:
            amount = Decimal('NaN')
        if not amount.is_finite() or not Decimal('0.0001') <= amount <= Decimal('1000000'):
            raise AdapterError('Configure a positive HUNTER_ESTIMATED_USD_PER_SEARCH covering the result cap before collection')
        return Cost(usd=float(amount), basis='per_call')

    def _limit(self, request: Request) -> int:
        value = request.params.get('limit', self.max_people)
        if isinstance(value, str) and value.isascii() and value.isdigit():
            value = int(value)
        if type(value) is not int or not 1 <= value <= self.max_people:
            raise AdapterError('Hunter request limit exceeds the configured result cap')
        return value

    def availability(self) -> dict:
        try:
            self.api_key()
            self.estimate_cost(Request('domain', 'example.com'))
        except AdapterError as exc:
            return {'available': False, 'reason': str(exc)}
        return {'available': True, 'reason': 'Configured; business emails only, with budget reservation required.'}

    def api_key(self) -> str:
        key = self._api_key or os.environ.get(API_KEY_ENV)
        if not key:
            raise AdapterError(
                f"{API_KEY_ENV} is not set; Hunter cannot run without it"
            )
        return key

    # ---- collection ------------------------------------------------------

    def search(self, request: Request) -> list[Reference]:
        domain = _domain(request.value)
        self.api_key()
        self.estimate_cost(request)
        limit = self._limit(request)
        query = urllib.parse.urlencode({'domain': domain, 'limit': limit})
        return [Reference(
            url='https://api.hunter.io/v2/domain-search?' + query,
            origin_url=f'https://hunter.io/domain/{domain}', label=domain,
        )]

    def fetch(self, reference: Reference) -> RawResult:
        parts = urllib.parse.urlsplit(reference.url)
        params = urllib.parse.parse_qs(parts.query)
        if (parts.scheme != 'https' or parts.netloc != 'api.hunter.io'
                or parts.path != '/v2/domain-search' or parts.fragment
                or set(params) != {'domain', 'limit'}
                or any(len(values) != 1 for values in params.values())):
            raise AdapterError('Hunter reference must use the verified domain-search endpoint')
        domain = _domain(params['domain'][0])
        request = Request('domain', domain, params={'limit': params['limit'][0]})
        self.estimate_cost(request)
        try:
            body = http_get(reference.url, headers={'X-API-KEY': self.api_key()}, timeout=30)
        except Exception:
            raise AdapterError('Hunter fetch failed; check credentials, quota, and provider availability') from None
        payload = body.encode('utf-8', errors='replace')
        if len(payload) > MAX_PAYLOAD_BYTES:
            raise AdapterError('Hunter response exceeds the collection size limit')
        # Only allowlisted business fields enter the evidence store/cache.
        # Unexpected credential/password fields are discarded in memory.
        try:
            response = json.loads(payload)
            data = response.get('data') if isinstance(response, dict) else None
            if not isinstance(data, dict) or not isinstance(data.get('domain'), str):
                raise ValueError()
            if _domain(data['domain']) != domain:
                raise ValueError()
            clean = {'domain': domain}
            for field in ('pattern', 'webmail', 'disposable'):
                if type(data.get(field)) in (str, bool):
                    clean[field] = data[field]
            records = data.get('emails') or []
            if not isinstance(records, list):
                raise ValueError()
            clean['emails'] = [
                {field: record[field] for field in (
                    'value', 'first_name', 'last_name', 'position', 'seniority'
                ) if isinstance(record.get(field), str)}
                for record in records[:self._limit(request)]
                if isinstance(record, dict)
                and isinstance(record.get('value'), str)
                and record['value'].strip().lower().endswith('@' + domain)
            ]
            payload = json.dumps({'data': clean}).encode()
        except (ValueError, AdapterError, UnicodeError):
            raise AdapterError('Hunter returned invalid company-search data') from None
        return RawResult(
            payload=payload, request_url=reference.url, origin_url=f'https://hunter.io/domain/{domain}',
            http_status=200, content_type='application/json', collected_at=datetime.now(timezone.utc),
        )

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        domain = _domain(request.value)
        try:
            body = json.loads(raw.payload.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeError):
            raise AdapterError('Hunter returned unparseable JSON') from None

        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            raise AdapterError("Hunter response had no data object")

        if not isinstance(data.get('domain'), str) or _domain(data['domain']) != domain:
            raise AdapterError('Hunter response domain does not match the requested company')
        if data.get('webmail') is True or data.get('disposable') is True:
            return []
        records = data.get('emails') or []
        if not isinstance(records, list):
            raise AdapterError('Hunter response emails must be a list')
        drafts: list[FactDraft] = []

        pattern = data.get("pattern")
        if isinstance(pattern, str) and 0 < len(pattern) <= 200:
            # An org-level fact, not a person-level one: the shape of the
            # address, which is often all an analyst needs.
            drafts.append(
                FactDraft(
                    attribute="email.pattern",
                    value=str(pattern),
                    entity_kind="domain",
                    entity_name=domain,
                )
            )

        for record in records[:self._limit(request)]:
            if not isinstance(record, dict):
                continue
            value = record.get('value')
            if not isinstance(value, str):
                continue
            address = value.strip().lower()
            if address.count('@') != 1 or len(address) > 254:
                continue
            local, email_domain = address.split('@')
            if (email_domain != domain or not 1 <= len(local) <= 64
                    or local.startswith('.') or local.endswith('.') or '..' in local
                    or not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+", local)):
                continue

            first = record.get('first_name')
            last = record.get('last_name')
            first = first.strip()[:200] if isinstance(first, str) else ''
            last = last.strip()[:200] if isinstance(last, str) else ''
            person = " ".join(p for p in (first, last) if p) or address

            drafts.append(
                FactDraft(
                    attribute="person.business_email",
                    value=address,
                    entity_kind="person",
                    entity_name=person,
                    identity_key="email:" + address,
                    value_type="email",
                )
            )
            if isinstance(record.get('position'), str) and record['position'].strip():
                drafts.append(
                    FactDraft(
                        attribute="person.role",
                        value=record["position"].strip()[:300],
                        entity_kind="person",
                        entity_name=person,
                        identity_key="email:" + address,
                    )
                )
            if isinstance(record.get('seniority'), str) and record['seniority'].strip():
                drafts.append(
                    FactDraft(
                        attribute="person.seniority",
                        value=record["seniority"].strip()[:100],
                        entity_kind="person",
                        entity_name=person,
                        identity_key="email:" + address,
                    )
                )

        return drafts
