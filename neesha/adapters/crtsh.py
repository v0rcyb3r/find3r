"""crt.sh — Certificate Transparency logs. Tier A, free.

The cheapest high-yield source in the stack: CT logs are a public append-only
record of every certificate issued, so they reveal hostnames nobody meant to
publish. Certificate SANs in particular leak internal naming constantly.

Facts are emitted *about the subject domain* — ``acme.com`` has subdomain
``mail.acme.com`` — rather than about each host. That shape is what makes the
output corroboratable (a passive-DNS source asserting the same subdomain
agrees on the same attribute/value pair) and diffable (a subdomain appearing
in a later run is a new fact, which is a signal).
"""
from __future__ import annotations

import json
import urllib.parse
from datetime import timedelta
from typing import ClassVar

from neesha.adapters.base import (
    AdapterError,
    BaseAdapter,
    Cost,
    FactDraft,
    RawResult,
    Reference,
    Request,
)
from neesha.collectors.network import http_get

# CT data is a permanent public record, so it may be kept. The limit here is
# about staleness of *our copy*, not about licensing.
RETENTION_DAYS = 90


class CrtShAdapter(BaseAdapter):
    name: ClassVar[str] = "crt.sh"
    tier: ClassVar[str] = "A"
    collection_mode: ClassVar[str] = "third_party_passive"
    description: ClassVar[str] = "Certificate Transparency subdomains via crt.sh"
    source_type: ClassVar[str] = "osint"
    produces: ClassVar[frozenset[str]] = frozenset({"dns.subdomain", "tls.ct"})
    accepts: ClassVar[frozenset[str]] = frozenset({"company", "domain"})
    retention_days: ClassVar[int] = RETENTION_DAYS

    # crt.sh is slow and unmetered; a generous timeout beats a retry storm.
    timeout: ClassVar[int] = 60
    max_subdomains: ClassVar[int] = 2000

    def estimate_cost(self, request: Request) -> Cost:
        return Cost()

    def search(self, request: Request) -> list[Reference]:
        domain = request.value.strip().lower().rstrip(".")
        query = urllib.parse.quote("%." + domain)
        url = f"https://crt.sh/?q={query}&output=json"
        return [Reference(url=url, origin_url="https://crt.sh/", label=domain)]

    def fetch(self, reference: Reference) -> RawResult:
        try:
            body = http_get(reference.url, timeout=self.timeout)
        except Exception as exc:  # noqa: BLE001 - network failure is a gap
            raise AdapterError(f"crt.sh fetch failed: {exc}") from exc
        return RawResult(
            payload=body.encode("utf-8", errors="replace"),
            request_url=reference.url,
            origin_url=reference.origin_url,
            http_status=200,
            content_type="application/json",
        )

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        domain = request.value.strip().lower().rstrip(".")
        try:
            entries = json.loads(raw.payload.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise AdapterError(f"crt.sh returned unparseable JSON: {exc}") from exc
        if not isinstance(entries, list):
            raise AdapterError("crt.sh returned an unexpected shape")

        subdomains: set[str] = set()
        issuers: set[str] = set()
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            for line in (entry.get("name_value") or "").split("\n"):
                host = line.strip().lower().lstrip("*.").rstrip(".")
                # Keep only names inside the subject domain. CT entries
                # routinely carry unrelated SANs from shared certificates,
                # and those belong to someone else's attack surface.
                if host and host != domain and host.endswith("." + domain):
                    subdomains.add(host)
            issuer = (entry.get("issuer_name") or "").strip()
            if issuer:
                issuers.add(issuer)

        drafts = [
            FactDraft(
                attribute="dns.subdomain",
                value=host,
                entity_kind="domain",
                entity_name=domain,
                value_type="domain",
            )
            for host in sorted(subdomains)[: self.max_subdomains]
        ]
        drafts += [
            FactDraft(
                attribute="tls.ct.issuer",
                value=issuer,
                entity_kind="domain",
                entity_name=domain,
            )
            for issuer in sorted(issuers)
        ]
        return drafts
