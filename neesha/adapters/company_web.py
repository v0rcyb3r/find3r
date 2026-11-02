"""Published company contacts and professional roles from public company pages.

No search-provider key, generated email addresses, or personal-profile scraping.
Requests are restricted to the seed host (and its www alias), globally routable
addresses, standard ports, and a small number of linked company pages.
"""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import ClassVar
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

import certifi

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request

MAX_BYTES = 512_000
MAX_PAGES = 5
MAX_SECONDS = 35
SECURITY_HEADERS = (
    'strict-transport-security', 'content-security-policy', 'x-content-type-options',
    'x-frame-options', 'referrer-policy', 'permissions-policy',
)
EMAIL = re.compile(r"[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9.-]*[A-Z0-9])?\.[A-Z]{2,63}", re.I)
PAGE_WORDS = re.compile(r'(?:about|team|leadership|management|contact|company|people)', re.I)


def _domain(value: str) -> str:
    value = value.strip().lower().rstrip('.')
    if any(c in value for c in '/:@?#\\') or '.' not in value:
        raise AdapterError('Company website collection requires a domain.')
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise AdapterError('Invalid company domain.') from exc
    if len(value) > 253 or any(not label or len(label) > 63 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label)
           for label in value.split('.')):
        raise AdapterError('Invalid company domain.')
    return value


def _validate_url(url: str, domain: str) -> tuple[str, int, str]:
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError as exc:
        raise AdapterError('Invalid website port.') from exc
    if (parts.scheme not in ('http', 'https') or parts.username or parts.password
            or parts.hostname not in (domain, 'www.' + domain)
            or port not in (None, 80 if parts.scheme == 'http' else 443)):
        raise AdapterError('Website request outside the company scope was blocked.')
    return parts.hostname, port or (443 if parts.scheme == 'https' else 80), parts.scheme


def _public_addresses(host: str, port: int) -> list[str]:
    try:
        addresses = sorted({row[4][0] for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except OSError as exc:
        raise AdapterError('Company website DNS lookup failed.') from exc
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise AdapterError('Private or non-public website addresses were blocked.')
    return addresses


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout)
        self.address = address

    def connect(self):
        self.sock = socket.create_connection((self.address, self.port), self.timeout)


class _PinnedHTTPS(_PinnedHTTP):
    def connect(self):
        sock = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = ssl.create_default_context(cafile=certifi.where()).wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def safe_fetch(url: str, domain: str, *, deadline: float) -> tuple[str, str, dict]:
    """Fetch without proxy use, automatic redirects, or a second DNS resolution.

    Each redirect is revalidated and its connection pinned to a public address.
    TLS still validates the actual hostname. No cookies or credentials are sent.
    """
    for _ in range(4):
        host, port, scheme = _validate_url(url, domain)
        addresses = _public_addresses(host, port)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise AdapterError('Company website collection time limit reached.')
        connection = (_PinnedHTTPS if scheme == 'https' else _PinnedHTTP)(host, port, addresses[0], min(8, remaining))
        parts = urlsplit(url)
        path = urlunsplit(('', '', parts.path or '/', parts.query, ''))
        try:
            connection.request('GET', path, headers={
                'Host': host, 'User-Agent': 'NEESHA/0.1 (public business research)',
                'Accept': 'text/html,application/xhtml+xml', 'Accept-Encoding': 'identity',
            })
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                if not location:
                    raise AdapterError('Company website returned an invalid redirect.')
                url = urljoin(url, location)
                continue
            if response.status != 200:
                raise AdapterError(f'Company website returned HTTP {response.status}.')
            if response.getheader('Content-Encoding', 'identity').lower() not in ('identity', ''):
                raise AdapterError('Unsupported company website content encoding.')
            mime = response.getheader('Content-Type', '').lower()
            if not any(t in mime for t in ('text/html', 'application/xhtml+xml')):
                raise AdapterError('Company website response was not HTML.')
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise AdapterError('Company website page exceeded the size limit.')
            headers = {name: response.getheader(name) for name in SECURITY_HEADERS
                       if response.getheader(name) is not None}
            return url, body.decode('utf-8', errors='replace'), {
                'status': response.status, 'security_headers': headers,
                'tls_validated': scheme == 'https',
            }
        except AdapterError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise AdapterError('Company website request failed.') from exc
        finally:
            connection.close()
    raise AdapterError('Company website redirect limit reached.')


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.emails: set[str] = set()
        self.phones: set[str] = set()
        self.scripts: list[str] = []
        self._json = False
        self._script = []
        self._hidden = 0
        self.visible: list[str] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('script', 'style'):
            self._hidden += 1
        if tag == 'script' and attrs.get('type', '').lower() == 'application/ld+json':
            self._json = True
            self._script = []
        if tag == 'a':
            href = attrs.get('href', '')
            if href.lower().startswith('mailto:'):
                self.emails.update(EMAIL.findall(unquote(href[7:].split('?')[0])))
            elif href.lower().startswith('tel:'):
                phone = unquote(href[4:]).strip()
                if 7 <= len(re.sub(r'\D', '', phone)) <= 18 and re.fullmatch(r'[+()\d .-]+', phone):
                    self.phones.add(phone)
            else:
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag == 'script' and self._json:
            self.scripts.append(''.join(self._script))
            self._json = False
        if tag in ('script', 'style'):
            self._hidden = max(0, self._hidden - 1)

    def handle_data(self, data):
        if self._json:
            self._script.append(data)
        if not self._hidden:
            self.visible.append(data)


def _business_email(value: str, domain: str) -> bool:
    match = EMAIL.fullmatch(value.strip())
    return bool(match and (value.rsplit('@', 1)[1].lower() == domain
                          or value.rsplit('@', 1)[1].lower().endswith('.' + domain)))


def _objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from _objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _objects(child)


class CompanyWebAdapter(BaseAdapter):
    name: ClassVar[str] = 'company-web'
    tier: ClassVar[str] = 'A'
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = 'direct_contact'
    source_type: ClassVar[str] = 'official'
    description: ClassVar[str] = 'Published company emails, telephone links and structured professional roles'
    produces: ClassVar[frozenset[str]] = frozenset({
        'company.business_email', 'company.business_phone', 'company.contact_page',
        'person.business_email', 'person.business_phone', 'person.role', 'person.profile_url',
        'http.status', 'http.final_url', 'http.security_header', 'http.security_assessed',
        'tls.connection.validated',
    })
    accepts: ClassVar[frozenset[str]] = frozenset({'company', 'domain'})
    retention_days: ClassVar[int] = 30

    def search(self, request: Request) -> list[Reference]:
        domain = _domain(request.value)
        return [Reference(url='https://' + domain + '/', origin_url='https://' + domain + '/',
                          params={'domain': domain}, label='Published company contacts')]

    def fetch(self, reference: Reference) -> RawResult:
        domain = _domain(str(reference.params.get('domain', urlsplit(reference.url).hostname or '')))
        deadline = time.monotonic() + MAX_SECONDS
        final_url, body, metadata = safe_fetch(reference.url, domain, deadline=deadline)
        pages = [{'url': final_url, 'html': body, **metadata}]
        parser = _Page()
        parser.feed(body)
        candidates = []
        for href in parser.links:
            url = urljoin(final_url, href)
            parts = urlsplit(url)
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, '', ''))
            if not PAGE_WORDS.search(parts.path) or url == final_url or url in candidates:
                continue
            try:
                _validate_url(url, domain)
            except AdapterError:
                continue
            candidates.append(url)
        for url in candidates[:MAX_PAGES - 1]:
            if time.monotonic() >= deadline:
                break
            try:
                page_url, page_body, metadata = safe_fetch(url, domain, deadline=deadline)
                pages.append({'url': page_url, 'html': page_body, **metadata})
            except AdapterError:
                continue  # Do not turn an unavailable page into a contact claim.
        # Redirect query strings can contain session/credential material. Keep
        # the public path as provenance, never persist query values/fragments.
        for page in pages:
            parts = urlsplit(page['url'])
            page['url'] = urlunsplit((parts.scheme, parts.netloc, parts.path, '', ''))
        final_url = pages[0]['url']
        return RawResult(payload=json.dumps({'domain': domain, 'pages': pages}).encode(),
                         request_url=final_url, origin_url=final_url, http_status=200,
                         content_type='application/json', collected_at=datetime.now(timezone.utc))

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        domain = _domain(request.value)
        try:
            bundle = json.loads(raw.payload)
        except (ValueError, UnicodeError) as exc:
            raise AdapterError('Invalid company website payload.') from exc
        facts: dict[tuple, FactDraft] = {}

        def add(attribute, value, *, name=None, identity_key=None):
            if not isinstance(value, str) or not value.strip():
                return
            fact = FactDraft(attribute=attribute, value=value.strip(),
                             entity_kind='person' if name else 'company', entity_name=name or domain,
                             identity_key=identity_key)
            facts[(fact.entity_kind, fact.entity_name, attribute, fact.value)] = fact

        if not isinstance(bundle, dict) or not isinstance(bundle.get('pages'), list):
            raise AdapterError('Invalid company website payload shape.')
        # Header observations describe the actual homepage response, never an
        # assumed missing control. Retain the response URL for analyst review.
        homepage = bundle['pages'][0] if bundle['pages'] else {}
        if isinstance(homepage, dict):
            if isinstance(homepage.get('status'), int):
                add('http.status', str(homepage['status']))
                add('http.final_url', homepage.get('url', ''))
                # The homepage was fetched, so its security headers were
                # observed in full: a header now absent is absent, not merely
                # uncollected. This marker is what lets scoring read it so.
                add('http.security_assessed', 'true')
            if homepage.get('tls_validated') is True:
                add('tls.connection.validated', 'true')
            headers = homepage.get('security_headers', {})
            if isinstance(headers, dict):
                for name in SECURITY_HEADERS:
                    value = headers.get(name)
                    if isinstance(value, str) and len(value) <= 8192:
                        add('http.security_header.' + name, value)
        for page in bundle['pages'][:MAX_PAGES]:
            if not isinstance(page, dict) or not isinstance(page.get('html'), str):
                continue
            parser = _Page()
            parser.feed(page.get('html', ''))
            emails = parser.emails | set(EMAIL.findall(' '.join(parser.visible)))
            published = False
            for email in sorted(emails):
                if _business_email(email, domain):
                    add('company.business_email', email.lower())
                    published = True
            for phone in sorted(parser.phones):
                add('company.business_phone', phone)
                published = True
            for script in parser.scripts:
                try:
                    objects = _objects(json.loads(script))
                    for obj in objects:
                        kinds = obj.get('@type', [])
                        if isinstance(kinds, str):
                            kinds = [kinds]
                        name, role = obj.get('name'), obj.get('jobTitle')
                        if 'Person' not in kinds or not isinstance(name, str) or not isinstance(role, str):
                            continue
                        if not name.strip() or not role.strip() or len(name) > 150 or len(role) > 200:
                            continue
                        # A guest author or speaker is not necessarily staff.
                        # Require a company-domain email or explicit worksFor URL.
                        email = obj.get('email', '')
                        company_email = (isinstance(email, str) and
                                         _business_email(email.removeprefix('mailto:'), domain))
                        employer = obj.get('worksFor', {})
                        employers = employer if isinstance(employer, list) else [employer]
                        company_employer = any(
                            isinstance(e, dict) and isinstance(e.get('url'), str)
                            and urlsplit(e['url']).hostname in (domain, 'www.' + domain)
                            for e in employers
                        )
                        if not company_email and not company_employer:
                            continue
                        person_key = ('email:' + email.removeprefix('mailto:').lower()
                                      if company_email else 'published-person:' + hashlib.sha256(
                                          (page.get('url','') + json.dumps(obj,sort_keys=True)).encode()
                                      ).hexdigest())
                        add('person.role', role, name=name, identity_key=person_key)
                        add('person.profile_url', page.get('url', ''), name=name, identity_key=person_key)
                        email = obj.get('email', '')
                        if isinstance(email, str) and _business_email(email.removeprefix('mailto:'), domain):
                            add('person.business_email', email.removeprefix('mailto:').lower(), name=name, identity_key=person_key)
                        phone = obj.get('telephone')
                        if isinstance(phone, str) and 7 <= len(re.sub(r'\D', '', phone)) <= 18 and re.fullmatch(r'[+()\d .-]+', phone):
                            add('person.business_phone', phone, name=name, identity_key=person_key)
                        published = True
                except (ValueError, TypeError, RecursionError):
                    continue
            if published:
                add('company.contact_page', page.get('url', ''))
        return list(facts.values())
