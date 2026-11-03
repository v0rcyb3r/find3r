"""Public commit-email publication, not an account-registration probe.

Contract: https://docs.github.com/en/rest/search/search#search-commits and
https://docs.github.com/en/search-github/searching-on-github/searching-commits
A commit author field is user-supplied metadata. It does not prove mailbox
ownership, legal identity, employment, or current account registration.
"""
from __future__ import annotations

import re
from typing import ClassVar
from urllib.parse import urlencode, urlsplit

from neesha.adapters.base import AdapterError, BaseAdapter, Reference, Request
from neesha.adapters.email_public import fact, get_json, normalize_email, result, stored_json


class GitHubEmailAdapter(BaseAdapter):
    name: ClassVar[str] = 'github-email'
    tier: ClassVar[str] = 'A'
    default_enabled: ClassVar[bool] = True
    collection_mode: ClassVar[str] = 'third_party_passive'
    source_type: ClassVar[str] = 'osint'
    description: ClassVar[str] = 'Exact supplied email in public GitHub commit metadata; not registration proof'
    accepts: ClassVar[frozenset[str]] = frozenset({'email'})
    produces: ClassVar[frozenset[str]] = frozenset({'public.email.github'})
    retention_days: ClassVar[int] = 7
    max_results: ClassVar[int] = 20

    def availability(self):
        return {'available': True, 'reason': 'Keyless public commit search; limited coverage and provider rate limits apply.'}

    def search(self, request: Request):
        email = normalize_email(request.value)
        query = urlencode({'q': 'author-email:' + email + ' is:public',
                           'per_page': self.max_results, 'page': 1})
        return [Reference(url='https://api.github.com/search/commits?' + query,
                          origin_url='https://github.com/', label=email)]

    def fetch(self, reference):
        email = normalize_email(reference.label)
        if reference.url != self.search(Request('email', email))[0].url:
            raise AdapterError('GitHub public lookup reference does not match the email')
        data, status = get_json(reference.url, source='GitHub', headers={
            'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2026-03-10'})
        if not isinstance(data, dict) or not isinstance(data.get('items'), list):
            raise AdapterError('GitHub returned an unexpected public-search response')
        matches = []
        for item in data['items'][:self.max_results]:
            if not isinstance(item, dict):
                continue
            repository = item.get('repository')
            commit = item.get('commit')
            if not isinstance(repository, dict) or repository.get('private') is not False or not isinstance(commit, dict):
                continue
            author = commit.get('author')
            if not isinstance(author, dict):
                continue
            try:
                if normalize_email(author.get('email')) != email:
                    continue
            except AdapterError:
                continue
            url = item.get('html_url')
            if not isinstance(url, str):
                continue
            parsed = urlsplit(url)
            if (parsed.scheme != 'https' or parsed.netloc != 'github.com'
                    or not re.fullmatch(r'/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commit/[a-fA-F0-9]{40,64}', parsed.path)
                    or parsed.query or parsed.fragment):
                continue
            match = {'commit_url': url}
            repo_name = repository.get('full_name')
            if isinstance(repo_name, str) and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo_name):
                match['repo'] = repo_name[:200]
            date = author.get('date')
            if isinstance(date, str) and date.strip():
                match['commit_date'] = date.strip()[:64]
            name = author.get('name')
            if isinstance(name, str) and name.strip():
                match['author_name'] = name.strip()[:200]
            linked = item.get('author')
            login = linked.get('login') if isinstance(linked, dict) else None
            if isinstance(login, str) and re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?', login):
                match['linked_login'] = login
            if match not in matches:
                matches.append(match)
        return result({'email': email, 'matches': matches,
                       'incomplete_results': data.get('incomplete_results') is True}, reference, status)

    def parse(self, raw, request):
        email = normalize_email(request.value)
        data = stored_json(raw)
        if data.get('email') != email or not isinstance(data.get('matches'), list):
            raise AdapterError('GitHub public metadata does not match the email')
        facts = []
        seen = set()
        for match in data['matches'][:self.max_results]:
            if not isinstance(match, dict):
                continue
            for key in ('commit_url', 'repo', 'commit_date', 'author_name', 'linked_login'):
                value = match.get(key)
                if not isinstance(value, str) or not value or (key, value) in seen:
                    continue
                seen.add((key, value))
                facts.append(fact(email, 'public.email.github.' + key, value))
        return facts
