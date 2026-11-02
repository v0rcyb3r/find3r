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

    def parse(self, raw, request):
        try:
            results = json.loads(raw.payload)
        except (ValueError, TypeError) as exc:
            raise AdapterError('Invalid DNS response.') from exc
        if not isinstance(results, list):
            raise AdapterError('Unexpected DNS response shape.')
        domain = request.value.rstrip('.').lower()
        facts = []
        for row in results:
            if not isinstance(row,dict) or row.get('status') != 'ok':
                continue  # A lookup failure is never evidence of a missing control.
            name, rtype, records = row.get('name'), row.get('type'), row.get('records', [])
            if not isinstance(records,list):
                continue
            records = [v for v in records if isinstance(v,str)]
            if name == domain and rtype in ('A','AAAA','MX','NS','CAA'):
                facts += [FactDraft(attribute='dns.'+rtype.lower(),value=v) for v in records[:100]]
            if rtype == 'TXT' and name == domain:
                candidates = list(dict.fromkeys(v for v in records if re.match(r'^v=spf1(?:\s|$)', v)))
                facts += [FactDraft(attribute='email.spf.record', value=v) for v in candidates]
                # Multiple SPF records are invalid; do not imply enforcement.
                if len(candidates) == 1:
                    spf = parse_spf(candidates)
                    if spf.qualifier != 'unknown':
                        facts.append(FactDraft(attribute='email.spf.qualifier',value=spf.qualifier))
            if rtype == 'TXT' and name == '_dmarc.'+domain:
                candidates = list(dict.fromkeys(v for v in records if re.match(r'^v=DMARC1(?:\s*;|$)', v, re.I)))
                facts += [FactDraft(attribute='email.dmarc.record', value=v) for v in candidates]
                # Conflicting/duplicate policies are not evidence of enforcement.
                if len(candidates) == 1:
                    dmarc = parse_dmarc(candidates)
                    if dmarc.policy in ('none','quarantine','reject'):
                        facts.append(FactDraft(attribute='email.dmarc.policy',value=dmarc.policy))
        return facts
