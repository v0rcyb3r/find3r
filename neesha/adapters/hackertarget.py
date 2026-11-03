"""Free HackerTarget passive hostsearch adapter for subdomains and IPv4 resolutions."""
from __future__ import annotations

import ipaddress
import re
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import ClassVar

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request
from neesha.collectors.network import _default_context


def _domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise AdapterError("HackerTarget requires a valid company domain")
    return domain


class HackerTargetAdapter(BaseAdapter):
    name: ClassVar[str] = "hackertarget"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "osint"
    description: ClassVar[str] = "HackerTarget passive hostsearch for subdomains and IPv4 addresses (free)"
    produces: ClassVar[frozenset[str]] = frozenset({"dns.subdomain", "dns.passive.ipv4"})
    accepts: ClassVar[frozenset[str]] = frozenset({"company", "domain"})
    retention_days: ClassVar[int] = 30
    max_payload_bytes: ClassVar[int] = 1024 * 1024
    timeout: ClassVar[int] = 15

    def search(self, request: Request) -> list[Reference]:
        domain = _domain(request.value)
        url = "https://api.hackertarget.com/hostsearch/?q=" + urllib.parse.quote(domain, safe="")
        return [Reference(url=url, origin_url="https://hackertarget.com/", label=domain)]

    def fetch(self, reference: Reference) -> RawResult:
        req = urllib.request.Request(reference.url, headers={"User-Agent": "NEESHA/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=_default_context()) as response:
                payload = response.read(self.max_payload_bytes + 1)
                if len(payload) > self.max_payload_bytes:
                    raise AdapterError("HackerTarget response exceeds size limit")
                return RawResult(
                    payload=payload,
                    request_url=reference.url,
                    origin_url=reference.origin_url,
                    http_status=response.status,
                    content_type="text/plain",
                    collected_at=datetime.now(timezone.utc),
                )
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError("HackerTarget hostsearch request failed") from exc

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        text = raw.payload.decode("utf-8", errors="replace").strip()
        if not text or text.lower().startswith(("error", "api count exceeded")):
            return []
        domain = _domain(request.value)
        hosts = set()
        ips = set()
        for line in text.splitlines()[:500]:
            if "," not in line:
                continue
            host_part, ip_part = line.split(",", 1)
            host = host_part.strip().lower().rstrip(".")
            ip_str = ip_part.strip()
            if not (host == domain or host.endswith("." + domain)):
                continue
            if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                continue
            if host != domain:
                hosts.add(host)
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.version == 4:
                    ips.add((host, str(ip_obj)))
            except ValueError:
                pass
        facts = [
            FactDraft(attribute="dns.subdomain", value=h, value_type="domain", entity_kind="domain", entity_name=domain)
            for h in sorted(hosts)
        ]
        facts += [
            FactDraft(attribute="dns.passive.ipv4", value=ip, value_type="ip", entity_kind="domain", entity_name=h)
            for h, ip in sorted(ips)
        ]
        return facts
