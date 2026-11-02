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

    def _dmarc_facts(self, by_key, domain, domain_exists):
        """DMARC with organizational-domain inheritance.

        A subdomain with no record of its own inherits its parent's policy, so
        the effective policy is read from the most specific ancestor that
        publishes one. 'absent' is claimed only when the domain exists and no
        ancestor publishes a DMARC record, with every ancestor lookup a
        confident no-record answer (a timeout anywhere leaves it unknown).
        """
        ancestors = _dmarc_ancestors(domain)
        all_no_record = domain_exists
        for name in ancestors:
            row = by_key.get((name, 'TXT'))
            records = [v for v in (row.get('records') or []) if isinstance(v, str)] if isinstance(row, dict) else []
            candidates = list(dict.fromkeys(
                v for v in records if re.match(r'^v=DMARC1(?:\s*;|$)', v, re.I)))
            if len(candidates) == 1:
                # The most specific published policy wins; stop walking up.
                facts = [FactDraft(attribute='email.dmarc.record', value=candidates[0])]
                dmarc = parse_dmarc(candidates)
                if dmarc.policy in ('none', 'quarantine', 'reject'):
                    facts.append(FactDraft(attribute='email.dmarc.policy', value=dmarc.policy))
                return facts
            if candidates:
                # Conflicting records at this level: present but ambiguous.
                return [FactDraft(attribute='email.dmarc.record', value=v) for v in candidates]
            if (not isinstance(row, dict) or row.get('status') not in self._NO_RECORD
                    or _attempts(records, 'dmarc')):
                # A timeout or a malformed attempt at any level is not a
                # confident absence for the inherited policy.
                all_no_record = False
        if all_no_record and ancestors:
            return [FactDraft(attribute='email.dmarc.policy', value='absent')]
        return []
