"""Passive OSINT collectors.

Each collector hits one public source, authorizes it through the scope engine,
and writes provenance-first Evidence (source_type="osint", graded C/3, capped
at Medium by the guardrail unless corroborated). External-tool adapters
(theHarvester, SpiderFoot) run only when the binary is installed; otherwise
they skip without writing evidence.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import urllib.parse
from typing import ClassVar, Optional

from neesha.collectors.base import Collector
from neesha.collectors.network import http_get, http_get_json
from neesha.evidence.models import (
    AdmiraltyClaimGrade,
    AdmiraltySourceGrade,
    CollectionMode,
    Confidence,
    Evidence,
)
from neesha.scope.engine import ScopeViolation


class PassiveCollector(Collector):
    agent = "osint"
    source: ClassVar[str] = "osint"
    description: ClassVar[str] = ""

    def fetch(self, url: str, headers: Optional[dict] = None, timeout: int = 20) -> str:
        self.authorize(self.source, CollectionMode.PASSIVE)
        return http_get(url, headers=headers, timeout=timeout)

    def fetch_json(self, url: str, headers: Optional[dict] = None, timeout: int = 20):
        self.authorize(self.source, CollectionMode.PASSIVE)
        return http_get_json(url, headers=headers, timeout=timeout)

    def record_osint(self, claim: str, source_url: str, is_inference: bool = False) -> Evidence:
        return self.record(
            claim=claim,
            source_type="osint",
            source_url=source_url,
            confidence=Confidence.MEDIUM,
            source_grade=AdmiraltySourceGrade.C,
            claim_grade=AdmiraltyClaimGrade.THREE,
            is_inference=is_inference,
        )

    def _error(self, message: str) -> list[Evidence]:
        if self.audit is not None:
            self.audit.log({
                "action": "collection-error",
                "agent": self.agent,
                "collector": self.name,
                "target": self.target,
                "source": self.source,
                "mode": "passive",
                "scope_id": self.scope.scope.scope_id,
                "reason": message,
            })
        return []


class CrtShCollector(PassiveCollector):
    name = "crt.sh"
    source = "crt.sh"
    description = "Certificate Transparency subdomains via crt.sh"

    def run(self) -> list[Evidence]:
        domain = self.target
        url = f"https://crt.sh/?q={urllib.parse.quote('%25.' + domain)}&output=json"
        try:
            data = self.fetch_json(url, timeout=60)
        except ScopeViolation:
            raise
        except Exception as exc:  # noqa: BLE001
            return self._error(f"crt.sh query failed: {exc}")
        if not isinstance(data, list):
            return self._error("crt.sh returned no results")
        subs = self._extract_subs(data, domain)
        claim = (
            f"crt.sh reports {len(subs)} subdomains for {domain}: "
            + (", ".join(subs[:20]) + ("..." if len(subs) > 20 else ""))
        )
        return [self.record_osint(claim, url)]

    @staticmethod
    def _extract_subs(data: list, domain: str) -> list[str]:
        subs = set()
        for entry in data:
            for line in (entry.get("name_value") or "").split("\n"):
                line = line.strip().lstrip("*.").lower()
                if line and (line == domain or line.endswith("." + domain)):
                    subs.add(line)
        return sorted(subs)


class OtxCollector(PassiveCollector):
    name = "otx"
    source = "otx"
    description = "AlienVault OTX passive DNS"

    def run(self) -> list[Evidence]:
        domain = self.target
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        try:
            data = self.fetch_json(url)
        except ScopeViolation:
            raise
        except Exception as exc:  # noqa: BLE001
            return self._error(f"OTX query failed: {exc}")
        entries = data.get("passive_dns", []) if isinstance(data, dict) else []
        hostnames = sorted({e.get("hostname") for e in entries if e.get("hostname")})
        addresses = sorted({e.get("address") for e in entries if e.get("address")})
        claim = (
            f"OTX passive DNS for {domain}: {len(entries)} records; "
            f"hosts: {', '.join(hostnames[:10]) or 'none'}; "
            f"addresses: {', '.join(addresses[:10]) or 'none'}"
        )
        return [self.record_osint(claim, url)]


class WaybackCollector(PassiveCollector):
    name = "wayback"
    source = "wayback"
    description = "Wayback Machine CDX archived URLs"

    def run(self) -> list[Evidence]:
        domain = self.target
        url = (
            f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
            f"&output=json&fl=timestamp,original,statuscode&collapse=urlkey&limit=100"
        )
        try:
            data = self.fetch_json(url)
        except ScopeViolation:
            raise
        except Exception as exc:  # noqa: BLE001
            return self._error(f"Wayback CDX query failed: {exc}")
        rows = data[1:] if isinstance(data, list) and data else []
        urls = sorted({row[1] for row in rows if len(row) >= 2})
        hosts = sorted({urllib.parse.urlparse(u).netloc for u in urls})
        claim = (
            f"Wayback Machine has {len(urls)} archived URLs for {domain} "
            f"across {len(hosts)} hosts: {', '.join(hosts[:15]) or 'none'}"
        )
        return [self.record_osint(claim, url)]


class UrlscanCollector(PassiveCollector):
    name = "urlscan"
    source = "urlscan"
    description = "urlscan.io domain search"

    def run(self) -> list[Evidence]:
        domain = self.target
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
        headers = {}
        api_key = os.environ.get("URLSCAN_API_KEY")
        if api_key:
            headers["API-Key"] = api_key
        try:
            data = self.fetch_json(url, headers=headers)
        except ScopeViolation:
            raise
        except Exception as exc:  # noqa: BLE001
            return self._error(f"urlscan query failed: {exc}")
        results = data.get("results", []) if isinstance(data, dict) else []
        domains = sorted({
            r.get("page", {}).get("domain") for r in results if r.get("page", {}).get("domain")
        })
        claim = (
            f"urlscan.io shows {len(results)} results for {domain}; "
            f"domains: {', '.join(domains[:15]) or 'none'}"
        )
        return [self.record_osint(claim, url)]


class HackerTargetCollector(PassiveCollector):
    name = "hackertarget"
    source = "hackertarget"
    description = "HackerTarget host search"

    def run(self) -> list[Evidence]:
        domain = self.target
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            text = self.fetch(url)
        except ScopeViolation:
            raise
        except Exception as exc:  # noqa: BLE001
            return self._error(f"HackerTarget query failed: {exc}")
        hosts = []
        for line in text.splitlines():
            line = line.strip()
            if "," in line and not line.lower().startswith(("error", "api")):
                host = line.split(",")[0]
                if host:
                    hosts.append(host)
        claim = (
            f"HackerTarget host search for {domain}: {len(hosts)} hosts "
            + (", ".join(hosts[:15]) or "none")
        )
        return [self.record_osint(claim, url)]


class TheHarvesterCollector(PassiveCollector):
    name = "theharvester"
    source = "theharvester"
    description = "theHarvester (external tool; skips if not installed)"

    def run(self) -> list[Evidence]:
        domain = self.target
        if shutil.which("theHarvester") is None:
            return []
        self.authorize(self.source, CollectionMode.PASSIVE)
        cmd = ["theHarvester", "-d", domain, "-b", "crtsh,otx"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        except Exception as exc:  # noqa: BLE001
            return self._error(f"theHarvester failed: {exc}")
        lines = result.stdout.strip().splitlines() if result.stdout else []
        claim = f"theHarvester collected {len(lines)} lines for {domain} (sources: crtsh, otx)"
        return [self.record_osint(claim, f"tool://theharvester/{domain}")]
