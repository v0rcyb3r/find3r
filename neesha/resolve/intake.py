"""Typed seed intake without network access or speculative identity resolution.

An extracted email domain is a research candidate, not proof of employment.
Names, IPs and phone numbers remain unresolved until corroborating sources
are available. This module never guesses whether a name is a person/company.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

KINDS = frozenset({'auto', 'website', 'domain', 'email', 'ip', 'phone', 'name', 'person', 'company', 'username'})
_USERNAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
_PUBLIC_MAILBOX_DOMAINS = frozenset({
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'yahoo.ca',
    'yahoo.co.in', 'ymail.com', 'rocketmail.com', 'outlook.com', 'hotmail.com',
    'hotmail.co.uk', 'live.com', 'msn.com', 'icloud.com', 'me.com', 'mac.com',
    'aol.com', 'proton.me', 'protonmail.com', 'pm.me', 'tutanota.com', 'tuta.com',
    'tuta.io', 'fastmail.com', 'hey.com', 'mail.com', 'gmx.com', 'gmx.de',
    'yandex.com', 'yandex.ru', 'zoho.com',
})
_LOCAL_PART = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+")
_PHONE = re.compile(r'\+?[0-9(][0-9() .-]*')
_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?')


def _input(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError('Enter a nonempty seed of at most 2048 characters.')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Seed must not contain control characters.')
    return value.strip()


def _domain(value):
    value = value.strip().rstrip('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('Enter a valid domain name.') from exc
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or any(
        not label or len(label) > 63 or not _LABEL.fullmatch(label) for label in labels
    ) or labels[-1].isdigit():
        raise ValueError('Enter a valid domain name with at least two labels.')
    return value


def _result(kind, normalized, *, domain=None, unresolved=True, reason, candidates=None, candidate=False):
    return {'kind': kind, 'normalized': normalized, 'domain': domain,
            'requires_resolution': unresolved, 'reason': reason,
            'candidate_domains': candidates or [], 'domain_is_candidate': candidate}


def _website(value):
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
            raise ValueError('Enter an HTTP(S) website with a hostname.')
        if parts.username is not None or parts.password is not None:
            raise ValueError('Website credentials are not accepted.')
        port = parts.port
        if port is not None and port < 1:
            raise ValueError('Enter a valid website port.')
        host = parts.hostname.rstrip('.').lower()
    except ValueError as exc:
        raise ValueError(str(exc) or 'Enter a valid HTTP(S) website.') from exc
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if not address.is_global:
            raise ValueError('Private or non-public IP website addresses are not accepted.')
        literal = '[' + address.compressed + ']' if address.version == 6 else address.compressed
        normalized = urlunsplit((parts.scheme.lower(), literal + (':' + str(port) if port else ''),
                                 parts.path or '/', '', ''))
        return _result('website', normalized, reason='Public IP website recognized; company association requires corroborating evidence.')
    domain = _domain(host)
    normalized = urlunsplit((parts.scheme.lower(), domain + (':' + str(port) if port else ''),
                             parts.path or '/', '', ''))
    return _result('website', normalized, domain=domain, unresolved=False,
        reason='Website hostname is available for domain research; legal company ownership is not established.')


def resolve_seed(value, kind='auto') -> dict:
    """Classify an identifier and return a safe research starting point.

    Corporate-email candidates allow domain research but never create a person
    or affiliation claim. Public mailbox providers, IPs, phones and names stay
    unresolved. Website query/fragment values are omitted from normalized output
    to avoid retaining session tokens. No DNS, provider, or model call occurs.
    """
    value = _input(value)
    if kind not in KINDS:
        raise ValueError('Unknown seed kind. Choose auto, website, domain, email, ip, phone, name, person, or company.')
    if kind == 'auto':
        if re.match(r'^[a-z][a-z0-9+.-]*://', value, re.I):
            kind = 'website'
        elif '@' in value:
            kind = 'email'
        else:
            try:
                ipaddress.ip_address(value)
                kind = 'ip'
            except ValueError:
                if re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', value):
                    kind = 'ip'
                elif re.fullmatch(r'[+0-9() .-]+', value):
                    kind = 'phone'
                elif '.' in value and not any(c.isspace() for c in value):
                    kind = 'domain'
                else:
                    kind = 'name'
    if kind == 'website':
        return _website(value)
    if kind == 'domain':
        # Domain inputs must not smuggle ports, paths or literal IPs into a run.
        try:
            ipaddress.ip_address(value.rstrip('.'))
        except ValueError:
            pass
        else:
            raise ValueError('An IP address is not a domain; use the IP seed type.')
        domain = _domain(value)
        return _result('domain', domain, domain=domain, unresolved=False,
            reason='Domain is available for research; company ownership and person affiliation remain unverified.')
    if kind == 'email':
        if value.count('@') != 1:
            raise ValueError('Enter a valid business email address.')
        local, host = value.rsplit('@', 1)
        if (not _LOCAL_PART.fullmatch(local) or len(local) > 64 or local.startswith('.')
                or local.endswith('.') or '..' in local):
            raise ValueError('Enter a valid unquoted email address.')
        domain = _domain(host)
        normalized = local + '@' + domain
        if len(normalized) > 254:
            raise ValueError('Email address is too long.')
        if any(domain == provider or domain.endswith('.' + provider) for provider in _PUBLIC_MAILBOX_DOMAINS):
            return _result('email', normalized, unresolved=False,
                reason='Exact email accepted for independent public-source research. A public mailbox provider does not identify an organization; no provider-domain research is authorized.')
        return _result('email', normalized, unresolved=False, candidates=[domain], candidate=True,
            reason='Exact email accepted for independent public-source research. The domain is only a separate research candidate; it does not identify a named person or establish company affiliation.')
    if kind == 'username':
        # Usernames are explicit subjects, never auto-classified from a name.
        # Case is preserved; a username is not proof of a real-world identity.
        candidate = value.strip()
        if not _USERNAME.fullmatch(candidate):
            raise ValueError('Enter a valid username (letters, digits, dot, dash, underscore; 1-64 chars).')
        return _result('username', candidate, unresolved=False,
            reason='Username accepted as an explicit research subject. It does not establish a real-world identity, account ownership, or company affiliation.')
    if kind == 'ip':
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError('Enter a valid IPv4 or IPv6 address.') from exc
        return _result('ip', address.compressed, unresolved=False,
            reason=('IP recognized for infrastructure & RDAP/Shodan research.'
                    if address.is_global else 'Non-public IP recognized; it does not identify a public company infrastructure owner.'))
    if kind == 'phone':
        if not _PHONE.fullmatch(value):
            raise ValueError('Enter a phone number containing digits and standard phone punctuation.')
        balance = 0
        for character in value:
            balance += (1 if character == '(' else -1 if character == ')' else 0)
            if balance < 0:
                raise ValueError('Phone number parentheses must be balanced.')
        if balance:
            raise ValueError('Phone number parentheses must be balanced.')
        digits = re.sub(r'[^0-9]', '', value)
        if not 7 <= len(digits) <= 15:
            raise ValueError('Phone numbers must contain between 7 and 15 digits.')
        normalized = ('+' if value.startswith('+') else '') + digits
        return _result('phone', normalized, unresolved=False,
            reason='Phone number normalized for OSINT correlation.')
    return _result(kind, ' '.join(value.split()), unresolved=(kind == 'name'),
        reason=('Name is ambiguous; specify person, company, or username to disambiguate.'
                if kind == 'name' else f'{kind.capitalize()} name accepted as a research subject.'))
