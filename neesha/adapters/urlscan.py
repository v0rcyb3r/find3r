"""Search existing urlscan observations; never submit a scan."""
import json
from typing import ClassVar
from urllib.parse import quote, urlparse
from urllib.request import Request as HTTPRequest, urlopen

import certifi
import ssl

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference


class UrlscanAdapter(BaseAdapter):
    name = 'urlscan'
    description = 'Existing public urlscan hostname observations (search only)'
    source_type = 'osint'
    default_enabled = False
    produces: ClassVar[frozenset[str]] = frozenset({'dns.subdomain', 'web.observed.url'})

    def search(self, request):
        return [Reference(url='https://urlscan.io/api/v1/search/?q='+quote('domain:'+request.value)+'&size=100',
                          origin_url='https://urlscan.io/')]

    def fetch(self, reference):
        try:
            req = HTTPRequest(reference.url, headers={'User-Agent':'neesha/0.1'})
            with urlopen(req,timeout=12,context=ssl.create_default_context(cafile=certifi.where())) as response:
                body = response.read(2_000_001)
            if len(body) > 2_000_000:
                raise AdapterError('urlscan response exceeded the collection limit.')
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError('urlscan search unavailable or rate-limited.') from exc
        return RawResult(payload=body,request_url=reference.url,origin_url=reference.origin_url,
                         content_type='application/json')

    def parse(self, raw, request):
        try:
            data = json.loads(raw.payload)
        except (ValueError,TypeError) as exc:
            raise AdapterError('urlscan returned invalid JSON.') from exc
        if not isinstance(data,dict) or not isinstance(data.get('results'),list):
            raise AdapterError('urlscan returned an unexpected response.')
        domain=request.value.lower().rstrip('.')
        found=set()
        for row in data['results'][:100]:
            if not isinstance(row,dict) or not isinstance(row.get('page'),dict):
                continue
            page=row['page']
            url=page.get('url')
            try:
                parts = urlparse(url) if isinstance(url, str) else None
                if (parts is None or parts.scheme not in ('http', 'https')
                        or parts.username or parts.password or not parts.hostname):
                    continue
                # Accessing .port validates malformed/out-of-range ports.
                if parts.port is not None and parts.port < 1:
                    continue
                host = parts.hostname.lower().rstrip('.')
            except ValueError:
                continue
            if host != domain and not host.endswith('.' + domain):
                continue
            if host != domain:
                found.add(('dns.subdomain', host))
            # Query strings can contain session identifiers; retain only the public path.
            found.add(('web.observed.url', parts._replace(query='', fragment='').geturl()))
        return [FactDraft(attribute=a,value=v,entity_name=domain) for a,v in sorted(found)]
