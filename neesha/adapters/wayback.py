"""Free Wayback CDX discovery, explicitly historical rather than live exposure."""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import ClassVar

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request
from neesha.collectors.network import _default_context, redact_url


class WaybackAdapter(BaseAdapter):
    default_enabled = False
    name: ClassVar[str] = 'wayback'
    tier: ClassVar[str] = 'A'
    collection_mode: ClassVar[str] = 'third_party_passive'
    source_type: ClassVar[str] = 'osint'
    description: ClassVar[str] = 'Wayback CDX historical URLs and hostnames (free)'
    produces: ClassVar[frozenset[str]] = frozenset({'web.archive.url', 'dns.subdomain'})
    accepts: ClassVar[frozenset[str]] = frozenset({'company', 'domain'})
    retention_days: ClassVar[int] = 30
    max_rows: ClassVar[int] = 500
    max_payload_bytes: ClassVar[int] = 2 * 1024 * 1024
    timeout: ClassVar[int] = 20

    def search(self, request: Request) -> list[Reference]:
        domain = request.value.strip().lower().rstrip('.')
        query = urllib.parse.urlencode({
            'url': domain, 'matchType': 'domain', 'output': 'json',
            'fl': 'timestamp,original,statuscode', 'collapse': 'urlkey',
            'limit': self.max_rows,
        })
        return [Reference(url='https://web.archive.org/cdx/search/cdx?' + query,
                          origin_url='https://web.archive.org/', label=domain)]

    def fetch(self, reference: Reference) -> RawResult:
        request = urllib.request.Request(reference.url, headers={'User-Agent': 'NEESHA/0.1'})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=_default_context()) as response:
                payload = response.read(self.max_payload_bytes + 1)
                if len(payload) > self.max_payload_bytes:
                    raise AdapterError('Wayback response exceeds the collection size limit')
                return RawResult(payload=payload, request_url=reference.url,
                                 origin_url=reference.origin_url, http_status=response.status,
                                 content_type='application/json', collected_at=datetime.now(timezone.utc))
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError('Wayback CDX request failed') from exc

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        if len(raw.payload) > self.max_payload_bytes:
            raise AdapterError('Wayback response exceeds the collection size limit')
        try:
            data = json.loads(raw.payload)
        except (ValueError, UnicodeError) as exc:
            raise AdapterError('Wayback returned invalid JSON') from exc
        if not isinstance(data, list):
            raise AdapterError('Wayback returned an unexpected response shape')
        if not data:
            return []
        header = data[0]
        if not isinstance(header, list) or 'original' not in header or 'timestamp' not in header:
            raise AdapterError('Wayback response is missing CDX column headers')
        url_index, time_index = header.index('original'), header.index('timestamp')
        domain = request.value.strip().lower().rstrip('.')
        urls, hosts = set(), set()
        for row in data[1:self.max_rows + 1]:
            if not isinstance(row, list) or len(row) <= max(url_index, time_index):
                continue
            url, timestamp = row[url_index], row[time_index]
            if (not isinstance(url, str) or len(url) > 4096
                    or not isinstance(timestamp, str) or not re.fullmatch(r'[0-9]{14}', timestamp)):
                continue
            try:
                datetime.strptime(timestamp, '%Y%m%d%H%M%S')
                parsed = urllib.parse.urlsplit(url)
                host = (parsed.hostname or '').lower().rstrip('.')
            except ValueError:
                continue
            if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password:
                continue
            if not host or not (host == domain or host.endswith('.' + domain)):
                continue
            if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                   for label in host.split('.')):
                continue
            # Archive URLs may contain credentials or fragments. They are not
            # fetched, and credential query values must not enter exported facts.
            safe_url = redact_url(urllib.parse.urlunsplit(parsed._replace(fragment='')))
            urls.add(safe_url)
            if host != domain:
                hosts.add(host)
        drafts = [FactDraft(attribute='web.archive.url', value=url,
                            entity_kind='domain', entity_name=domain)
                  for url in sorted(urls)]
        drafts += [FactDraft(attribute='dns.subdomain', value=host, value_type='domain',
                             entity_kind='domain', entity_name=domain)
                   for host in sorted(hosts)]
        return drafts
