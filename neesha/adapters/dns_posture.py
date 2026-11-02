"""Keyless DNS posture observations through the existing dnspython resolver."""
import json
import re
from typing import ClassVar

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference
from neesha.posture.parsers import parse_dmarc, parse_spf
from neesha.resolvers.dns import SystemResolver


def _dmarc_ancestors(domain: str) -> list[str]:
    """`_dmarc.<name>` for the domain and each parent down to a two-label base.

    A subdomain inherits the organizational domain's DMARC policy, so absence
    can only be asserted after checking the parents too. The single-label TLD
    is never queried. Ordered most specific first.
    """
    labels = domain.split('.')
    return ['_dmarc.' + '.'.join(labels[i:]) for i in range(len(labels) - 1)]


def _attempts(records, mechanism: str) -> bool:
    """True if a record looks like a (possibly malformed) attempt at SPF/DMARC.

    Tolerant on purpose — quotes and whitespace are stripped and the version
    token is matched anywhere — so a broken record withholds an 'absent' claim
    and leaves the result unknown rather than falsely reporting no record.
    """
    for value in records:
        text = value.strip().strip('"').strip()
        if re.search(r'v\s*=\s*' + mechanism, text, re.I) or re.search(mechanism + r'1', text, re.I):
            return True
    return False


class DnsPostureAdapter(BaseAdapter):
    name = 'dns-posture'
    description = 'DNS infrastructure and published SPF/DMARC records'
    source_type = 'dns'
    collection_mode = 'direct_contact'
    retention_days = 1
    default_enabled = False
    produces: ClassVar[frozenset[str]] = frozenset({
        'dns.a', 'dns.aaaa', 'dns.mx', 'dns.ns', 'dns.caa',
        'email.spf.record', 'email.spf.qualifier', 'email.dmarc.record', 'email.dmarc.policy',
    })

    def search(self, request):
        return [Reference(url='dns://' + request.value.rstrip('.').lower())]

    def fetch(self, reference):
        domain = reference.url.removeprefix('dns://')
        resolver = SystemResolver()
        results = []
        # DMARC is published on the organizational domain and inherited by
        # subdomains, so query _dmarc up the ancestor chain (stopping before
        # the single-label TLD). SPF is per-exact-domain and is not walked.
        queries = [(domain, t) for t in ('A', 'AAAA', 'MX', 'NS', 'CAA', 'TXT')]
        queries += [(name, 'TXT') for name in _dmarc_ancestors(domain)]
        for name, rtype in queries:
            result = resolver.query(name, rtype)
            results.append({'name':name,'type':rtype,'status':result.status,
                            'records':[r.value for r in result.records]})
        if all(r['status'] == 'error' for r in results):
            raise AdapterError('DNS resolvers did not answer; posture is unknown.')
        return RawResult(payload=json.dumps(results).encode(), request_url=reference.url,
                         origin_url=reference.url, content_type='application/json')

    # A confident answer from the resolver that the name exists but has no such
    # record, as opposed to a transport failure (unknown) or the name not
    # existing at all (NXDOMAIN — see _domain_exists).
    _NO_RECORD = frozenset({'ok', 'noerror-nodata'})

    def parse(self, raw, request):
        try:
            results = json.loads(raw.payload)
        except (ValueError, TypeError) as exc:
            raise AdapterError('Invalid DNS response.') from exc
        if not isinstance(results, list):
            raise AdapterError('Unexpected DNS response shape.')
        domain = request.value.rstrip('.').lower()
        by_key: dict[tuple, dict] = {}
        for row in results:
            if isinstance(row, dict):
                by_key[(row.get('name'), row.get('type'))] = row
        facts = []
        # Positive infrastructure observations only: a lookup failure here is
        # never recorded as evidence of a missing host.
        for rtype in ('A', 'AAAA', 'MX', 'NS', 'CAA'):
            row = by_key.get((domain, rtype))
            if not row or row.get('status') != 'ok':
                continue
            records = [v for v in (row.get('records') or []) if isinstance(v, str)]
            facts += [FactDraft(attribute='dns.' + rtype.lower(), value=v) for v in records[:100]]
        # An 'absent' control is only meaningful for a domain that exists. If
        # the name itself does not resolve, the posture is unknown, not absent.
        domain_exists = self._domain_exists(by_key, domain)
        facts += self._spf_facts(by_key.get((domain, 'TXT')), domain_exists)
        facts += self._dmarc_facts(by_key, domain, domain_exists)
        return facts

    @staticmethod
    def _domain_exists(by_key, domain) -> bool:
        for rtype in ('A', 'AAAA', 'NS', 'MX', 'TXT'):
            row = by_key.get((domain, rtype))
            if row and row.get('status') in DnsPostureAdapter._NO_RECORD:
                return True
        return False

    def _spf_facts(self, row, domain_exists):
        if not isinstance(row, dict):
            return []
        records = [v for v in (row.get('records') or []) if isinstance(v, str)]
        candidates = list(dict.fromkeys(v for v in records if re.match(r'^v=spf1(?:\s|$)', v)))
        facts = [FactDraft(attribute='email.spf.record', value=v) for v in candidates]
        if len(candidates) == 1:
            # Multiple SPF records are invalid; do not imply enforcement.
            spf = parse_spf(candidates)
            if spf.qualifier != 'unknown':
                facts.append(FactDraft(attribute='email.spf.qualifier', value=spf.qualifier))
        elif (not candidates and domain_exists and row.get('status') in self._NO_RECORD
              and not _attempts(records, 'spf')):
            # The domain exists and the resolver confirms no SPF record is
            # published. SPF has no organizational-domain fallback, so this
            # absence is an observation. A malformed attempt stays unknown.
            facts.append(FactDraft(attribute='email.spf.qualifier', value='absent'))
        return facts

    # For a _dmarc lookup specifically, NXDOMAIN is the ordinary way a name
    # publishes no DMARC record, so it is a confident no-record answer here
    # (the apex's existence is established separately by _domain_exists).
    _DMARC_NO_RECORD = frozenset({'ok', 'noerror-nodata', 'nxdomain'})

    def _dmarc_facts(self, by_key, domain, domain_exists):
        """DMARC with organizational-domain inheritance.

        Walk _dmarc from the queried name up its ancestors. The most specific
        published policy governs; when it comes from an ancestor above the
        queried domain, the subdomain policy (sp=) applies if set, else p=.
        'absent' is claimed only when the domain exists and every level up the
        chain is a confident no-record answer. A lookup that errors at a more
        specific level than any published policy leaves the result unknown:
        we cannot tell whether that level publishes its own record, so a
        parent's policy must not be inherited past an unknown.
        """
        if not domain_exists:
            return []
        ancestors = _dmarc_ancestors(domain)
        for depth, name in enumerate(ancestors):
            row = by_key.get((name, 'TXT'))
            if not isinstance(row, dict) or row.get('status') not in self._DMARC_NO_RECORD:
                return []  # error/timeout at this level: unknown, do not inherit
            records = [v for v in (row.get('records') or []) if isinstance(v, str)]
            candidates = list(dict.fromkeys(
                v for v in records if re.match(r'^v=DMARC1(?:\s*;|$)', v, re.I)))
            if len(candidates) == 1:
                dmarc = parse_dmarc(candidates)
                # Above the queried domain, sp= governs subdomains (fallback p=).
                policy = (dmarc.subdomain_policy or dmarc.policy) if depth else dmarc.policy
                facts = [FactDraft(attribute='email.dmarc.record', value=candidates[0])]
                if policy in ('none', 'quarantine', 'reject'):
                    facts.append(FactDraft(attribute='email.dmarc.policy', value=policy))
                return facts
            if candidates:
                # Conflicting records at this level: present but ambiguous.
                return [FactDraft(attribute='email.dmarc.record', value=v) for v in candidates]
            if _attempts(records, 'dmarc'):
                return []  # present but malformed at this level: unknown, not absent
            # No record at this level; inherit from the parent.
        return [FactDraft(attribute='email.dmarc.policy', value='absent')] if ancestors else []
