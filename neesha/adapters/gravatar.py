"""Public Gravatar profile metadata addressed by the supplied email's SHA256.

Contract: https://docs.gravatar.com/rest/api-data-specifications/ and
https://docs.gravatar.com/rest-api/. No avatars, hidden accounts, contact
fields, payments, recovery endpoints, or private profile data are collected.
"""
from __future__ import annotations

import hashlib
import re
from typing import ClassVar
from urllib.parse import urlsplit

from neesha.adapters.base import AdapterError, BaseAdapter, Reference, Request
from neesha.adapters.email_public import fact, get_json, normalize_email, result, stored_json


def email_hash(email):
    return hashlib.sha256(normalize_email(email).lower().encode()).hexdigest()


class GravatarAdapter(BaseAdapter):
    name: ClassVar[str] = 'gravatar'
    tier: ClassVar[str] = 'A'
    default_enabled: ClassVar[bool] = True
    collection_mode: ClassVar[str] = 'third_party_passive'
    source_type: ClassVar[str] = 'osint'
    description: ClassVar[str] = 'Public Gravatar profile for the supplied email hash; no registration inference'
    accepts: ClassVar[frozenset[str]] = frozenset({'email'})
    produces: ClassVar[frozenset[str]] = frozenset({'public.profile.gravatar'})
    retention_days: ClassVar[int] = 7

    def availability(self):
        return {'available': True, 'reason': 'Keyless public profile API; no profile can mean absent or private, not no account.'}

    def search(self, request):
        email = normalize_email(request.value)
        return [Reference(url='https://api.gravatar.com/v3/profiles/' + email_hash(email),
                          origin_url='https://gravatar.com/', label=email)]

    def fetch(self, reference):
        email = normalize_email(reference.label)
        if reference.url != self.search(Request('email', email))[0].url:
            raise AdapterError('Gravatar public lookup reference does not match the email')
        data, status = get_json(reference.url, source='Gravatar', allow_not_found=True)
        if status == 404:
            return result({'email': email, 'profile': None}, reference, status)
        if not isinstance(data, dict) or data.get('hash') != email_hash(email):
            raise AdapterError('Gravatar profile hash does not match the supplied email')
        profile_url = data.get('profile_url')
        if not isinstance(profile_url, str):
            raise AdapterError('Gravatar public profile URL is missing')
        parsed = urlsplit(profile_url)
        if (parsed.scheme != 'https' or parsed.netloc not in ('gravatar.com', 'www.gravatar.com')
                or not re.fullmatch(r'/[A-Za-z0-9_.-]+/?', parsed.path)
                or parsed.query or parsed.fragment):
            raise AdapterError('Gravatar returned an invalid public profile URL')
        profile = {'url': profile_url}
        # Only explicitly visible linked accounts on the public profile. This
        # records a published link, not registration or mailbox ownership.
        visibility = data.get('section_visibility')
        hidden = isinstance(visibility, dict) and visibility.get('hidden_verified_accounts') is True
        accounts = data.get('verified_accounts', [])
        links = set()
        if not hidden and isinstance(accounts, list):
            for account in accounts[:4]:
                if not isinstance(account, dict) or account.get('is_hidden') is not False:
                    continue
                link = account.get('url')
                if not isinstance(link, str) or len(link) > 2048:
                    continue
                try:
                    target = urlsplit(link)
                except ValueError:
                    continue
                if (target.scheme != 'https' or not target.hostname or target.username or target.password
                        or target.query or target.fragment):
                    continue
                links.add(link)
        profile['linked_profile_urls'] = sorted(links)
        name = data.get('display_name')
        if isinstance(name, str) and name.strip():
            profile['display_name'] = name.strip()[:200]
        return result({'email': email, 'profile': profile}, reference, status)

    def parse(self, raw, request):
        email = normalize_email(request.value)
        data = stored_json(raw)
        if data.get('email') != email:
            raise AdapterError('Gravatar public metadata does not match the email')
        profile = data.get('profile')
        if profile is None:
            return []
        if not isinstance(profile, dict):
            raise AdapterError('Invalid Gravatar public metadata')
        facts = [fact(email, 'public.profile.gravatar.' + key, profile[key])
                 for key in ('url', 'display_name') if isinstance(profile.get(key), str) and profile[key]]
        links = profile.get('linked_profile_urls', [])
        if isinstance(links, list):
            facts += [fact(email, 'public.profile.gravatar.linked_profile_url', link)
                      for link in links[:4] if isinstance(link, str) and link]
        return facts
