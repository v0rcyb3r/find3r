"""Optional existing-key EmailRep metadata, never credential/breach records.

Official current contract: https://docs.sublime.security/reference/emailrep-introduction
Unauthenticated access is disabled and the vendor issues no new keys. The
connector is therefore unavailable unless an existing EmailRep key is supplied.
Profile-type hints are provider inferences, not verified account-registration.
"""
from __future__ import annotations

import os
import re
from typing import ClassVar
from urllib.parse import quote

from neesha.adapters.base import AdapterError, BaseAdapter, Reference, Request
from neesha.adapters.email_public import fact, get_json, normalize_email, result, stored_json


class EmailRepAdapter(BaseAdapter):
    name: ClassVar[str] = 'emailrep'
    tier: ClassVar[str] = 'A'
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = 'third_party_passive'
    source_type: ClassVar[str] = 'osint_aggregate'
    description: ClassVar[str] = 'Optional EmailRep public reputation/profile hints; existing API key required'
    accepts: ClassVar[frozenset[str]] = frozenset({'email'})
    produces: ClassVar[frozenset[str]] = frozenset({'public.email.emailrep'})
    retention_days: ClassVar[int] = 7

    def availability(self):
        if not os.environ.get('EMAILREP_API_KEY'):
            return {'available': False, 'reason': 'EmailRep requires an existing API key; unauthenticated access is disabled and new keys are not issued.'}
        return {'available': True, 'reason': 'Existing-key access only; profile hints are unverified and rate limits vary by key.'}

    def search(self, request):
        email = normalize_email(request.value)
        return [Reference(url='https://emailrep.io/' + quote(email, safe=''),
                          origin_url='https://emailrep.io/', label=email)]

    def fetch(self, reference):
        email = normalize_email(reference.label)
        if reference.url != self.search(Request('email', email))[0].url:
            raise AdapterError('EmailRep lookup reference does not match the email')
        key = os.environ.get('EMAILREP_API_KEY')
        if not key:
            raise AdapterError(self.availability()['reason'])
        data, status = get_json(reference.url, source='EmailRep', headers={'Key': key})
        if not isinstance(data, dict):
            raise AdapterError('EmailRep returned an unexpected response')
        try:
            if normalize_email(data.get('email')) != email:
                raise AdapterError('EmailRep response does not match the supplied email')
        except AdapterError:
            raise AdapterError('EmailRep response does not match the supplied email') from None
        safe = {'email': email, 'profile_hints': []}
        if data.get('reputation') in ('high', 'medium', 'low', 'none'):
            safe['reputation'] = data['reputation']
        count = data.get('references')
        if type(count) is int and 0 <= count <= 1000000000:
            safe['reference_count'] = count
        details = data.get('details')
        hints = details.get('profiles', []) if isinstance(details, dict) else []
        if isinstance(hints, list):
            safe['profile_hints'] = sorted({
                h for h in hints[:50] if isinstance(h, str) and re.fullmatch(r'[a-z0-9_-]{1,40}', h)
            })
        # Credentials/breach flags, names, phones and all unknown fields are
        # intentionally discarded before RawResult, source records and cache.
        return result(safe, reference, status)

    def parse(self, raw, request):
        email = normalize_email(request.value)
        data = stored_json(raw)
        if data.get('email') != email:
            raise AdapterError('EmailRep public metadata does not match the email')
        facts = []
        reputation = data.get('reputation')
        if reputation in ('high', 'medium', 'low', 'none'):
            facts.append(fact(email, 'public.email.emailrep.reputation', reputation, is_inference=True))
        count = data.get('reference_count')
        if type(count) is int and count >= 0:
            facts.append(fact(email, 'public.email.emailrep.reference_count', str(count), value_type='int'))
        hints = data.get('profile_hints', [])
        if isinstance(hints, list):
            facts += [fact(email, 'public.email.emailrep.profile_hint', hint, is_inference=True)
                      for hint in hints[:50] if isinstance(hint, str) and re.fullmatch(r'[a-z0-9_-]{1,40}', hint)]
        return facts
