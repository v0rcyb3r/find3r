"""Keyless DNS & TLS posture observations through dnspython and TLS handshake inspection."""
import json
import re
from typing import ClassVar

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference
from neesha.posture.parsers import parse_dmarc, parse_mtasts, parse_spf, parse_tlsrpt
from neesha.resolvers.dns import SystemResolver

DKIM_SELECTORS = (
    'google', 'default', 'selector1', 'selector2', 'k1', 's1', 's2',
    'dkim', 'mail', 'mandrill', 'sendgrid', 'amazonses', 'protonmail',
    'zoho', 'everlytickey1',
)


def _dmarc_ancestors(domain: str) -> list[str]:
    """`_dmarc.<name>` for the domain and each parent down to a two-label base."""
    labels = domain.split('.')
    return ['_dmarc.' + '.'.join(labels[i:]) for i in range(len(labels) - 1)]


def _attempts(records, mechanism: str) -> bool:
    """True if a record looks like a (possibly malformed) attempt at SPF/DMARC."""
    for value in records:
        text = value.strip().strip('"').strip()
        if re.search(r'v\s*=\s*' + mechanism, text, re.I) or re.search(mechanism + r'1', text, re.I):
            return True
    return False


class DnsPostureAdapter(BaseAdapter):
    name = 'dns-posture'
    description = 'DNS infrastructure, SPF/DMARC/DKIM/MTA-STS/TLS-RPT, DNSSEC, and TLS certificate posture'
    source_type = 'dns'
    collection_mode = 'direct_contact'
    retention_days = 1
    default_enabled = False
    produces: ClassVar[frozenset[str]] = frozenset({
        'dns.a', 'dns.aaaa', 'dns.mx', 'dns.ns', 'dns.caa', 'dns.soa', 'dns.txt',
        'dnssec.status',
        'email.spf.record', 'email.spf.qualifier',
        'email.dmarc.record', 'email.dmarc.policy', 'email.dmarc.rua', 'email.dmarc.pct',
        'email.dkim.selector',
        'email.mtasts.record', 'email.mtasts.present',
        'email.tlsrpt.record', 'email.tlsrpt.present',
        'tls.issuer', 'tls.not_after', 'tls.days_remaining', 'tls.san',
    })

    def search(self, request):
        return [Reference(url='dns://' + request.value.rstrip('.').lower())]

    def fetch(self, reference):
        domain = reference.url.removeprefix('dns://')
        resolver = SystemResolver()
        results = []
        queries = [(domain, t) for t in ('A', 'AAAA', 'MX', 'NS', 'CAA', 'TXT')]
        queries += [(name, 'TXT') for name in _dmarc_ancestors(domain)]
        queries += [
            (domain, 'SOA'),
            (domain, 'DNSKEY'),
            (f'_mta-sts.{domain}', 'TXT'),
            (f'_smtp._tls.{domain}', 'TXT'),
        ]
        queries += [(f'{sel}._domainkey.{domain}', 'TXT') for sel in DKIM_SELECTORS]
        for name, rtype in queries:
            result = resolver.query(name, rtype)
            results.append({'name': name, 'type': rtype, 'status': result.status,
                            'records': [r.value for r in result.records]})
        if all(r['status'] == 'error' for r in results):
            raise AdapterError('DNS resolvers did not answer; posture is unknown.')

        # Optional live TLS certificate inspection when the domain resolves.
        has_host = any(
            r['name'] == domain and r['type'] in ('A', 'AAAA') and r['status'] == 'ok' and r['records']
            for r in results
        )
        if has_host:
            try:
                from neesha.collectors.network import get_tls_cert

                tls = get_tls_cert(domain, timeout=4.0)
                if tls.connected:
                    results.append({
                        'name': domain,
                        'type': '_TLS',
                        'status': 'ok',
                        'tls': {
                            'issuer': tls.issuer,
                            'not_after': tls.not_after.isoformat() if tls.not_after else None,
                            'days_remaining': tls.days_remaining,
                            'san': list(tls.san or [])[:100],
                        },
                    })
            except Exception:
                pass

        return RawResult(payload=json.dumps(results).encode(), request_url=reference.url,
                         origin_url=reference.url, content_type='application/json')

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
        for rtype in ('A', 'AAAA', 'MX', 'NS', 'CAA', 'SOA'):
            row = by_key.get((domain, rtype))
            if not row or row.get('status') != 'ok':
                continue
            records = [v for v in (row.get('records') or []) if isinstance(v, str)]
            attr = 'dns.' + rtype.lower()
            val_type = 'ip' if rtype in ('A', 'AAAA') else 'str'
            facts += [FactDraft(attribute=attr, value=v, value_type=val_type) for v in records[:100]]

        domain_exists = self._domain_exists(by_key, domain)

        # DNSKEY / DNSSEC
        dnskey_row = by_key.get((domain, 'DNSKEY'))
        if dnskey_row and dnskey_row.get('status') in self._NO_RECORD:
            if dnskey_row.get('records'):
                facts.append(FactDraft(attribute='dnssec.status', value='present'))
            elif domain_exists:
                facts.append(FactDraft(attribute='dnssec.status', value='absent'))

        facts += self._spf_facts(by_key.get((domain, 'TXT')), domain_exists)
        facts += self._dmarc_facts(by_key, domain, domain_exists)
        facts += self._mtasts_facts(by_key.get((f'_mta-sts.{domain}', 'TXT')), domain_exists)
        facts += self._tlsrpt_facts(by_key.get((f'_smtp._tls.{domain}', 'TXT')))
        facts += self._dkim_facts(by_key, domain)
        facts += self._tls_facts(by_key.get((domain, '_TLS')))
        return facts

    @staticmethod
    def _domain_exists(by_key, domain) -> bool:
        for rtype in ('A', 'AAAA', 'NS', 'MX', 'TXT', 'SOA'):
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
            spf = parse_spf(candidates)
            if spf.qualifier != 'unknown':
                facts.append(FactDraft(attribute='email.spf.qualifier', value=spf.qualifier))
        elif (not candidates and domain_exists and row.get('status') in self._NO_RECORD
              and not _attempts(records, 'spf')):
            facts.append(FactDraft(attribute='email.spf.qualifier', value='absent'))
        return facts

    _DMARC_NO_RECORD = frozenset({'ok', 'noerror-nodata', 'nxdomain'})

    def _dmarc_facts(self, by_key, domain, domain_exists):
        if not domain_exists:
            return []
        ancestors = _dmarc_ancestors(domain)
        for depth, name in enumerate(ancestors):
            row = by_key.get((name, 'TXT'))
            if not isinstance(row, dict) or row.get('status') not in self._DMARC_NO_RECORD:
                return []
            records = [v for v in (row.get('records') or []) if isinstance(v, str)]
            candidates = list(dict.fromkeys(
                v for v in records if re.match(r'^v=DMARC1(?:\s*;|$)', v, re.I)))
            if len(candidates) == 1:
                dmarc = parse_dmarc(candidates)
                policy = (dmarc.subdomain_policy or dmarc.policy) if depth else dmarc.policy
                facts = [FactDraft(attribute='email.dmarc.record', value=candidates[0])]
                if policy in ('none', 'quarantine', 'reject'):
                    facts.append(FactDraft(attribute='email.dmarc.policy', value=policy))
                if dmarc.rua:
                    facts.append(FactDraft(attribute='email.dmarc.rua', value=dmarc.rua))
                if dmarc.pct is not None and dmarc.pct != 100:
                    facts.append(FactDraft(attribute='email.dmarc.pct', value=str(dmarc.pct), value_type='int'))
                return facts
            if candidates:
                return [FactDraft(attribute='email.dmarc.record', value=v) for v in candidates]
            if _attempts(records, 'dmarc'):
                return []
        return [FactDraft(attribute='email.dmarc.policy', value='absent')] if ancestors else []

    @staticmethod
    def _mtasts_facts(row, domain_exists: bool = False) -> list[FactDraft]:
        if not isinstance(row, dict) or row.get('status') not in DnsPostureAdapter._DMARC_NO_RECORD:
            return []
        records = [v for v in (row.get('records') or []) if isinstance(v, str)]
        parsed = parse_mtasts(records)
        if parsed.present and parsed.record:
            return [
                FactDraft(attribute='email.mtasts.present', value='true', value_type='bool'),
                FactDraft(attribute='email.mtasts.record', value=parsed.record),
            ]
        if domain_exists:
            return [FactDraft(attribute='email.mtasts.present', value='absent')]
        return []

    @staticmethod
    def _tlsrpt_facts(row) -> list[FactDraft]:
        if not isinstance(row, dict) or row.get('status') != 'ok':
            return []
        records = [v for v in (row.get('records') or []) if isinstance(v, str)]
        parsed = parse_tlsrpt(records)
        if parsed.present and parsed.record:
            return [
                FactDraft(attribute='email.tlsrpt.present', value='true', value_type='bool'),
                FactDraft(attribute='email.tlsrpt.record', value=parsed.record),
            ]
        return []

    @staticmethod
    def _dkim_facts(by_key, domain) -> list[FactDraft]:
        facts = []
        for sel in DKIM_SELECTORS:
            row = by_key.get((f'{sel}._domainkey.{domain}', 'TXT'))
            if not isinstance(row, dict) or row.get('status') != 'ok':
                continue
            records = [v for v in (row.get('records') or []) if isinstance(v, str)]
            if any('v=dkim1' in r.lower() or 'p=' in r.lower() for r in records):
                facts.append(FactDraft(attribute='email.dkim.selector', value=sel))
        return facts

    @staticmethod
    def _tls_facts(row) -> list[FactDraft]:
        if not isinstance(row, dict) or row.get('status') != 'ok':
            return []
        tls = row.get('tls')
        if not isinstance(tls, dict):
            return []
        facts = []
        if isinstance(tls.get('issuer'), str) and tls['issuer'].strip():
            facts.append(FactDraft(attribute='tls.issuer', value=tls['issuer'].strip()))
        if isinstance(tls.get('not_after'), str) and tls['not_after'].strip():
            facts.append(FactDraft(attribute='tls.not_after', value=tls['not_after'].strip()))
        if isinstance(tls.get('days_remaining'), int):
            facts.append(FactDraft(attribute='tls.days_remaining', value=str(tls['days_remaining']), value_type='int'))
        for san in (tls.get('san') or [])[:50]:
            if isinstance(san, str) and san.strip():
                facts.append(FactDraft(attribute='tls.san', value=san.strip().lower()))
        return facts
