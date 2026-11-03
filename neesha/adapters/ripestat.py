"""Keyless RIPEstat BGP, ASN, and announced prefix intelligence adapter."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import ClassVar

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request
from neesha.collectors.network import _default_context
from neesha.runtime.providers import _NoRedirect


def _https_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=_default_context()),
        _NoRedirect(),
    )


def _domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise AdapterError("RIPEstat requires a valid domain or globally routable IP address")
    return domain


class RipestatAdapter(BaseAdapter):
    name: ClassVar[str] = "ripestat-asn"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "osint"
    description: ClassVar[str] = "RIPEstat BGP & ASN routing lookup for announced prefixes, origin ASNs, and ASN holders"
    produces: ClassVar[frozenset[str]] = frozenset({
        "host.asn",
        "host.asn_name",
        "host.cidr",
        "host.org",
        "bgp.prefix",
        "bgp.holder",
    })
    accepts: ClassVar[frozenset[str]] = frozenset({"ip", "domain", "company"})
    retention_days: ClassVar[int] = 14
    max_payload_bytes: ClassVar[int] = 512 * 1024
    timeout: ClassVar[int] = 12

    def search(self, request: Request) -> list[Reference]:
        val = request.value.strip().lower().rstrip(".")
        try:
            ip_obj = ipaddress.ip_address(val)
            if not ip_obj.is_global:
                raise AdapterError("RIPEstat requires a globally routable IP address")
            ip = ip_obj.compressed
            url = f"https://stat.ripe.net/data/network-info/data.json?resource={urllib.parse.quote(ip, safe='')}"
            return [Reference(url=url, origin_url="https://stat.ripe.net/", label=ip, params={"ip": ip})]
        except ValueError:
            domain = _domain(val)
            url = f"https://stat.ripe.net/data/network-info/data.json?resource={urllib.parse.quote(domain, safe='')}"
            return [Reference(url=url, origin_url="https://stat.ripe.net/", label=domain, params={"domain": domain})]

    def _fetch_json(self, url: str) -> dict:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Find3r/0.2", "Accept": "application/json"},
        )
        try:
            with _https_opener().open(req, timeout=self.timeout) as resp:
                payload = resp.read(self.max_payload_bytes + 1)
                if len(payload) > self.max_payload_bytes:
                    raise AdapterError("RIPEstat response exceeds size limit")
                parsed = json.loads(payload)
                return parsed if isinstance(parsed, dict) else {}
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError("RIPEstat request failed") from exc

    def _query_ip_bgp(self, ip: str) -> dict:
        net_url = f"https://stat.ripe.net/data/network-info/data.json?resource={urllib.parse.quote(ip, safe='')}"
        net_json = self._fetch_json(net_url)
        net_data = net_json.get("data") if isinstance(net_json.get("data"), dict) else {}
        prefix = str(net_data.get("prefix") or "").strip()
        asns_raw = net_data.get("asns") if isinstance(net_data.get("asns"), list) else []
        asns: list[str] = []
        for a in asns_raw[:5]:
            s = str(a).strip().upper()
            if s.isdigit():
                s = f"AS{s}"
            if re.fullmatch(r"AS\d{1,10}", s):
                asns.append(s)
        holder = ""
        if asns:
            try:
                ov_url = f"https://stat.ripe.net/data/as-overview/data.json?resource={urllib.parse.quote(asns[0], safe='')}"
                ov_json = self._fetch_json(ov_url)
                ov_data = ov_json.get("data") if isinstance(ov_json.get("data"), dict) else {}
                holder = str(ov_data.get("holder") or "").strip()
            except Exception:
                holder = ""
        return {
            "ip": ip,
            "prefix": prefix,
            "asns": asns,
            "holder": holder,
        }

    def fetch(self, reference: Reference) -> RawResult:
        params = reference.params or {}
        domain = params.get("domain")
        if domain:
            ips: list[str] = []
            try:
                infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
                for info in infos:
                    addr = info[4][0]
                    ip_obj = ipaddress.ip_address(addr)
                    if ip_obj.is_global and addr not in ips:
                        ips.append(addr)
                    if len(ips) >= 2:
                        break
            except Exception as exc:
                raise AdapterError(f"Could not resolve IPv4 for {domain}") from exc
            results = {}
            for ip in ips:
                results[ip] = self._query_ip_bgp(ip)
            return RawResult(
                payload=json.dumps({"results": results}).encode("utf-8"),
                request_url=reference.url,
                origin_url=reference.origin_url,
                http_status=200,
                content_type="application/json",
                collected_at=datetime.now(timezone.utc),
            )

        ip_target = params.get("ip") or reference.label or ""
        info = self._query_ip_bgp(ip_target)
        return RawResult(
            payload=json.dumps({"results": {ip_target: info}}).encode("utf-8"),
            request_url=reference.url,
            origin_url=reference.origin_url,
            http_status=200,
            content_type="application/json",
            collected_at=datetime.now(timezone.utc),
        )

    def _extract_ip_bgp_facts(self, ip: str, item: dict) -> list[FactDraft]:
        facts: list[FactDraft] = []
        prefix = str(item.get("prefix") or "").strip()
        if prefix:
            try:
                net = ipaddress.ip_network(prefix, strict=False)
                facts.append(FactDraft(attribute="host.cidr", value=str(net), entity_kind="ip", entity_name=ip))
                facts.append(FactDraft(attribute="bgp.prefix", value=str(net), entity_kind="ip", entity_name=ip))
            except ValueError:
                pass
        for asn in (item.get("asns") or [])[:5]:
            asn_str = str(asn).strip().upper()
            if asn_str.isdigit():
                asn_str = f"AS{asn_str}"
            if re.fullmatch(r"AS\d{1,10}", asn_str):
                facts.append(FactDraft(attribute="host.asn", value=asn_str, entity_kind="ip", entity_name=ip))
        holder = str(item.get("holder") or "").strip()
        if holder:
            facts.append(FactDraft(attribute="bgp.holder", value=holder[:160], entity_kind="ip", entity_name=ip))
            facts.append(FactDraft(attribute="host.org", value=holder[:160], entity_kind="ip", entity_name=ip))
            facts.append(FactDraft(attribute="host.asn_name", value=holder[:160], entity_kind="ip", entity_name=ip))
        return facts

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        if raw.http_status == 404 or raw.payload == b"{}":
            return []
        try:
            data = json.loads(raw.payload)
        except (ValueError, UnicodeError) as exc:
            raise AdapterError("RIPEstat returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise AdapterError("RIPEstat returned an unexpected response")

        if isinstance(data.get("results"), dict):
            facts: list[FactDraft] = []
            for ip_str, item in data["results"].items():
                if isinstance(item, dict):
                    try:
                        ip = ipaddress.ip_address(ip_str.strip()).compressed
                        facts.extend(self._extract_ip_bgp_facts(ip, item))
                    except ValueError:
                        continue
            return facts
        return []
