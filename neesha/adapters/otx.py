"""Free AlienVault OTX passive-DNS observations, not live DNS assertions."""
from __future__ import annotations

import ipaddress
import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import ClassVar

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request
from neesha.collectors.network import _default_context


class OtxAdapter(BaseAdapter):
    default_enabled = False
    name: ClassVar[str] = 'otx'
    tier: ClassVar[str] = 'A'
    collection_mode: ClassVar[str] = 'third_party_passive'
    source_type: ClassVar[str] = 'osint'
    description: ClassVar[str] = 'AlienVault OTX historical passive DNS (free)'
    produces: ClassVar[frozenset[str]] = frozenset({'dns.subdomain', 'dns.passive.ipv4', 'dns.passive.ipv6'})
    accepts: ClassVar[frozenset[str]] = frozenset({'company', 'domain'})
    retention_days: ClassVar[int] = 30
    max_rows: ClassVar[int] = 500
    max_payload_bytes: ClassVar[int] = 2 * 1024 * 1024
    timeout: ClassVar[int] = 20

    def search(self, request: Request) -> list[Reference]:
        domain = request.value.strip().lower().rstrip('.')
        url = ('https://otx.alienvault.com/api/v1/indicators/domain/'
               + urllib.parse.quote(domain, safe='') + '/passive_dns')
        return [Reference(url=url, origin_url='https://otx.alienvault.com/', label=domain)]

    def fetch(self, reference: Reference) -> RawResult:
        request = urllib.request.Request(reference.url, headers={'User-Agent': 'NEESHA/0.1'})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=_default_context()) as response:
                payload = response.read(self.max_payload_bytes + 1)
                if len(payload) > self.max_payload_bytes:
                    raise AdapterError('OTX response exceeds the collection size limit')
                return RawResult(payload=payload, request_url=reference.url,
                                 origin_url=reference.origin_url, http_status=response.status,
                                 content_type='application/json', collected_at=datetime.now(timezone.utc))
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError('OTX passive DNS request failed') from exc

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        if len(raw.payload) > self.max_payload_bytes:
            raise AdapterError('OTX response exceeds the collection size limit')
        try:
            data = json.loads(raw.payload)
        except (ValueError, UnicodeError) as exc:
            raise AdapterError('OTX returned invalid JSON') from exc
        if not isinstance(data, dict) or not isinstance(data.get('passive_dns'), list):
            raise AdapterError('OTX response is missing passive DNS records')
        domain = request.value.strip().lower().rstrip('.')
        hosts, addresses = set(), set()
        for row in data['passive_dns'][:self.max_rows]:
            if not isinstance(row, dict):
                continue
            host = row.get('hostname')
            if not isinstance(host, str) or len(host) > 253:
                continue
            host = host.strip().lower().rstrip('.')
            if not (host == domain or host.endswith('.' + domain)):
                continue
            if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                   for label in host.split('.')):
                continue
            address = row.get('address')
            if not isinstance(address, str):
                continue
            try:
                parsed_address = ipaddress.ip_address(address)
            except ValueError:
                continue
            if host != domain:
                hosts.add(host)
            addresses.add((host, parsed_address.version, str(parsed_address)))
        drafts = [FactDraft(attribute='dns.subdomain', value=host, value_type='domain',
                            entity_kind='domain', entity_name=domain)
                  for host in sorted(hosts)]
        drafts += [FactDraft(attribute=f'dns.passive.ipv{version}', value=address,
                             entity_kind='domain', entity_name=host, value_type='ip')
                   for host, version, address in sorted(addresses)]
        return drafts
