"""Keyless DNS posture observations through the existing dnspython resolver."""
import json
import re
from typing import ClassVar

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference
from neesha.posture.parsers import parse_dmarc, parse_spf
from neesha.resolvers.dns import SystemResolver


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
        for name, rtype in [(domain,t) for t in ('A','AAAA','MX','NS','CAA','TXT')] + [('_dmarc.'+domain,'TXT')]:
            result = resolver.query(name, rtype)
            results.append({'name':name,'type':rtype,'status':result.status,
                            'records':[r.value for r in result.records]})
        if all(r['status'] == 'error' for r in results):
            raise AdapterError('DNS resolvers did not answer; posture is unknown.')
        return RawResult(payload=json.dumps(results).encode(), request_url=reference.url,
                         origin_url=reference.url, content_type='application/json')

    # Statuses that are a confident answer from the resolver, as opposed to a
    # transport failure. An authoritative "this name has no such record" is
    # evidence the record is not published; a timeout is not.
    _ANSWERED = frozenset({'ok', 'nxdomain', 'noerror-nodata'})

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
        facts += self._spf_facts(by_key.get((domain, 'TXT')))
        facts += self._dmarc_facts(by_key.get(('_dmarc.' + domain, 'TXT')))
        return facts

    def _spf_facts(self, row):
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
        elif not candidates and row.get('status') in self._ANSWERED and not self._attempts(records, 'spf'):
            # The resolver answered authoritatively and nothing at the apex even
            # attempts SPF: the record is absent, an observation rather than a
            # missing lookup. A malformed attempt stays unknown, not "absent".
            facts.append(FactDraft(attribute='email.spf.qualifier', value='absent'))
        return facts

    def _dmarc_facts(self, row):
        if not isinstance(row, dict):
            return []
        records = [v for v in (row.get('records') or []) if isinstance(v, str)]
        candidates = list(dict.fromkeys(v for v in records if re.match(r'^v=DMARC1(?:\s*;|$)', v, re.I)))
        facts = [FactDraft(attribute='email.dmarc.record', value=v) for v in candidates]
        if len(candidates) == 1:
            # Conflicting/duplicate policies are not evidence of enforcement.
            dmarc = parse_dmarc(candidates)
            if dmarc.policy in ('none', 'quarantine', 'reject'):
                facts.append(FactDraft(attribute='email.dmarc.policy', value=dmarc.policy))
        elif not candidates and row.get('status') in self._ANSWERED and not self._attempts(records, 'dmarc'):
            facts.append(FactDraft(attribute='email.dmarc.policy', value='absent'))
        return facts

    @staticmethod
    def _attempts(records, mechanism: str) -> bool:
        """True if some record looks like a (possibly malformed) attempt at the
        mechanism, so we withhold an 'absent' claim and leave it unknown."""
        return any(re.match(r'^v=' + mechanism, v, re.I) for v in records)
