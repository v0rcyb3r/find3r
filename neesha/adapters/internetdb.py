"""Shodan InternetDB keyless IP enrichment: open ports, CPEs, hostnames, tags, CVEs."""
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
        raise AdapterError("InternetDB requires a valid domain or globally routable IP address")
    return domain


class InternetDbAdapter(BaseAdapter):
    name: ClassVar[str] = "internetdb"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "osint"
    description: ClassVar[str] = "Shodan (InternetDB + optional SHODAN_API_KEY) lookup for open ports, CPEs, Geo-IP coordinates, ASN/ISP, reverse DNS, and CVEs"
    produces: ClassVar[frozenset[str]] = frozenset({
        "host.port",
        "host.cpe",
        "host.reverse_dns",
        "host.tag",
        "host.vuln",
        "host.country",
        "host.city",
        "host.latitude",
        "host.longitude",
        "host.asn",
        "host.org",
        "host.isp",
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
                raise AdapterError("InternetDB requires a globally routable IP address")
            ip = ip_obj.compressed
            url = f"https://internetdb.shodan.io/{ip}"
            return [Reference(url=url, origin_url="https://internetdb.shodan.io/", label=ip)]
        except ValueError:
            domain = _domain(val)
            url = "https://internetdb.shodan.io/?host=" + urllib.parse.quote(domain, safe="")
            return [Reference(url=url, origin_url="https://internetdb.shodan.io/", label=domain, params={"domain": domain})]

    def _fetch_shodan_host_json(self, ip: str) -> dict:
        import os
        api_key = os.environ.get("SHODAN_API_KEY", "").strip()
        if not api_key:
            return {}
        try:
            ip_obj = ipaddress.ip_address(ip.strip())
            if not ip_obj.is_global:
                return {}
            clean_ip = ip_obj.compressed
        except ValueError:
            return {}
        url = f"https://api.shodan.io/shodan/host/{clean_ip}?key={urllib.parse.quote(api_key, safe='')}&minify=true"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Find3r/0.1", "Accept": "application/json"},
        )
        try:
            with _https_opener().open(req, timeout=self.timeout) as response:
                payload = response.read(self.max_payload_bytes + 1)
                if len(payload) > self.max_payload_bytes:
                    return {}
                data = json.loads(payload)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _merge_shodan_enrichment(self, ip: str, base_data: dict) -> dict:
        shodan_data = self._fetch_shodan_host_json(ip)
        if not shodan_data:
            return base_data
        merged = dict(base_data)
        merged.setdefault("ip", ip)
        for key in ("country_code", "city", "latitude", "longitude", "asn", "org", "isp"):
            if shodan_data.get(key) is not None and merged.get(key) is None:
                merged[key] = shodan_data[key]
        for list_key in ("ports", "hostnames", "tags", "vulns"):
            s_val = shodan_data.get(list_key)
            if isinstance(s_val, list):
                existing = list(merged.get(list_key) or [])
                for item in s_val:
                    if item not in existing:
                        existing.append(item)
                merged[list_key] = existing
        return merged

    def _fetch_ip_json(self, ip: str) -> dict:
        url = f"https://internetdb.shodan.io/{ip}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "NEESHA/0.1", "Accept": "application/json"},
        )
        data: dict = {}
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=_default_context()) as response:
                payload = response.read(self.max_payload_bytes + 1)
                if len(payload) > self.max_payload_bytes:
                    raise AdapterError("InternetDB response exceeds size limit")
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    data = parsed
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise AdapterError("InternetDB request failed") from exc
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError("InternetDB request failed") from exc
        return self._merge_shodan_enrichment(ip, data)

    def fetch(self, reference: Reference) -> RawResult:
        domain = (reference.params or {}).get("domain")
        if domain:
            ips: list[str] = []
            try:
                infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
                for info in infos:
                    addr = info[4][0]
                    ip_obj = ipaddress.ip_address(addr)
                    if ip_obj.is_global and addr not in ips:
                        ips.append(addr)
                    if len(ips) >= 3:
                        break
            except Exception as exc:
                raise AdapterError(f"Could not resolve IPv4 for {domain}") from exc
            if not ips:
                return RawResult(
                    payload=b"{}",
                    request_url=reference.url,
                    origin_url=reference.origin_url,
                    http_status=404,
                    content_type="application/json",
                    collected_at=datetime.now(timezone.utc),
                )
            results = {}
            for ip in ips:
                data = self._fetch_ip_json(ip)
                if data:
                    results[ip] = data
            return RawResult(
                payload=json.dumps({"results": results}).encode("utf-8"),
                request_url=reference.url,
                origin_url=reference.origin_url,
                http_status=200,
                content_type="application/json",
                collected_at=datetime.now(timezone.utc),
            )

        ip_target = (reference.label or "").strip()
        if not ip_target:
            ip_target = reference.url.rstrip("/").rsplit("/", 1)[-1]
        data = self._fetch_ip_json(ip_target)
        return RawResult(
            payload=(json.dumps(data).encode("utf-8") if data else b"{}"),
            request_url=reference.url,
            origin_url=reference.origin_url,
            http_status=200 if data else 404,
            content_type="application/json",
            collected_at=datetime.now(timezone.utc),
        )

    def _extract_ip_facts(self, ip: str, data: dict) -> list[FactDraft]:
        facts: list[FactDraft] = []
        for port in (data.get("ports") or [])[:100]:
            if type(port) is int and 1 <= port <= 65535:
                facts.append(FactDraft(attribute="host.port", value=str(port), value_type="int", entity_kind="ip", entity_name=ip))
        for cpe in (data.get("cpes") or [])[:50]:
            if isinstance(cpe, str) and cpe.strip():
                facts.append(FactDraft(attribute="host.cpe", value=cpe.strip()[:200], entity_kind="ip", entity_name=ip))
        for hostname in (data.get("hostnames") or [])[:50]:
            if isinstance(hostname, str) and hostname.strip():
                facts.append(FactDraft(attribute="host.reverse_dns", value=hostname.strip().lower().rstrip(".")[:253], entity_kind="ip", entity_name=ip))
        for tag in (data.get("tags") or [])[:30]:
            if isinstance(tag, str) and tag.strip():
                facts.append(FactDraft(attribute="host.tag", value=tag.strip()[:100], entity_kind="ip", entity_name=ip))
        for vuln in (data.get("vulns") or [])[:100]:
            if isinstance(vuln, str) and vuln.strip():
                facts.append(FactDraft(attribute="host.vuln", value=vuln.strip().upper()[:64], entity_kind="ip", entity_name=ip))
        cc = data.get("country_code") or data.get("country")
        if isinstance(cc, str) and len(cc.strip()) == 2:
            facts.append(FactDraft(attribute="host.country", value=cc.strip().upper(), entity_kind="ip", entity_name=ip))
        city = data.get("city")
        if isinstance(city, str) and city.strip():
            facts.append(FactDraft(attribute="host.city", value=city.strip()[:120], entity_kind="ip", entity_name=ip))
        lat = data.get("latitude")
        lon = data.get("longitude")
        if isinstance(lat, (int, float)) and not isinstance(lat, bool) and -90 <= float(lat) <= 90:
            facts.append(FactDraft(attribute="host.latitude", value=f"{float(lat):.4f}", value_type="float", entity_kind="ip", entity_name=ip))
        if isinstance(lon, (int, float)) and not isinstance(lon, bool) and -180 <= float(lon) <= 180:
            facts.append(FactDraft(attribute="host.longitude", value=f"{float(lon):.4f}", value_type="float", entity_kind="ip", entity_name=ip))
        for field_key, attr_name in (("asn", "host.asn"), ("org", "host.org"), ("isp", "host.isp")):
            val = data.get(field_key)
            if isinstance(val, (str, int)) and not isinstance(val, bool) and str(val).strip():
                facts.append(FactDraft(attribute=attr_name, value=str(val).strip()[:160], entity_kind="ip", entity_name=ip))
        return facts

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        if raw.http_status == 404 or raw.payload == b"{}":
            return []
        try:
            data = json.loads(raw.payload)
        except (ValueError, UnicodeError) as exc:
            raise AdapterError("InternetDB returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise AdapterError("InternetDB returned an unexpected response")

        if isinstance(data.get("results"), dict):
            facts: list[FactDraft] = []
            for ip_str, item in data["results"].items():
                if isinstance(item, dict):
                    try:
                        ip = ipaddress.ip_address(ip_str.strip()).compressed
                        facts.extend(self._extract_ip_facts(ip, item))
                    except ValueError:
                        continue
            return facts

        val = request.value.strip()
        try:
            ip = ipaddress.ip_address(data.get("ip") or val).compressed
        except ValueError as exc:
            raise AdapterError("InternetDB requires a valid IPv4 or IPv6 address") from exc
        return self._extract_ip_facts(ip, data)
