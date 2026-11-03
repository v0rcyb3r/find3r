"""Free keyless RDAP/WHOIS lookup for domains and IP addresses."""
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


def _domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise AdapterError("RDAP requires a valid domain or globally routable IP address")
    return domain


class RdapAdapter(BaseAdapter):
    name: ClassVar[str] = "rdap"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "official"
    description: ClassVar[str] = "RDAP / WHOIS registration, registrar, lifecycle dates, and IP network ownership"
    produces: ClassVar[frozenset[str]] = frozenset({
        "whois.registrar",
        "whois.created",
        "whois.expires",
        "whois.updated",
        "whois.status",
        "whois.nameserver",
        "host.network_name",
        "host.cidr",
        "host.country",
        "host.org",
    })
    accepts: ClassVar[frozenset[str]] = frozenset({"company", "domain", "ip"})
    retention_days: ClassVar[int] = 30
    max_payload_bytes: ClassVar[int] = 1024 * 1024
    timeout: ClassVar[int] = 15

    def search(self, request: Request) -> list[Reference]:
        val = request.value.strip().lower().rstrip(".")
        try:
            ip = ipaddress.ip_address(val)
            if not ip.is_global:
                raise AdapterError("RDAP requires a globally routable IP address")
            kind = "ip"
            target = ip.compressed
        except ValueError:
            kind = "domain"
            target = _domain(val)
        url = f"https://rdap.org/{kind}/" + urllib.parse.quote(target, safe="")
        return [Reference(url=url, origin_url="https://rdap.org/", label=target, params={"kind": kind})]

    def fetch(self, reference: Reference) -> RawResult:
        req = urllib.request.Request(
            reference.url,
            headers={"User-Agent": "NEESHA/0.1", "Accept": "application/rdap+json, application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=_default_context()) as response:
                payload = response.read(self.max_payload_bytes + 1)
                if len(payload) > self.max_payload_bytes:
                    raise AdapterError("RDAP response exceeds the collection size limit")
                return RawResult(
                    payload=payload,
                    request_url=reference.url,
                    origin_url=reference.origin_url,
                    http_status=response.status,
                    content_type="application/json",
                    collected_at=datetime.now(timezone.utc),
                )
        except AdapterError:
            raise
        except Exception as exc:
            raise AdapterError("RDAP lookup failed or record unavailable") from exc

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        if len(raw.payload) > self.max_payload_bytes:
            raise AdapterError("RDAP response exceeds the collection size limit")
        try:
            data = json.loads(raw.payload)
        except (ValueError, UnicodeError) as exc:
            raise AdapterError("RDAP returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise AdapterError("RDAP returned an unexpected response shape")

        target = request.value.strip().lower().rstrip(".")
        try:
            ip_obj = ipaddress.ip_address(target)
            if not ip_obj.is_global:
                raise AdapterError("RDAP requires a globally routable IP address")
            target = ip_obj.compressed
            is_ip = True
        except ValueError:
            target = _domain(target)
            is_ip = False

        entity_kind = "ip" if is_ip else "domain"
        facts: list[FactDraft] = []

        # Lifecycle events (registration, expiration, last changed)
        for ev in data.get("events") or []:
            if not isinstance(ev, dict):
                continue
            action = (ev.get("eventAction") or "").lower().strip()
            date = (ev.get("eventDate") or "").strip()
            if not date:
                continue
            if action in ("registration", "registered"):
                facts.append(FactDraft(attribute="whois.created", value=date[:64], entity_kind=entity_kind, entity_name=target))
            elif action in ("expiration", "expires"):
                facts.append(FactDraft(attribute="whois.expires", value=date[:64], entity_kind=entity_kind, entity_name=target))
            elif action in ("last changed", "last update of rdap database"):
                facts.append(FactDraft(attribute="whois.updated", value=date[:64], entity_kind=entity_kind, entity_name=target))

        # Status flags
        for st in (data.get("status") or [])[:10]:
            if isinstance(st, str) and st.strip():
                facts.append(FactDraft(attribute="whois.status", value=st.strip()[:100], entity_kind=entity_kind, entity_name=target))

        # Nameservers
        for ns in (data.get("nameservers") or [])[:20]:
            if isinstance(ns, dict) and isinstance(ns.get("ldhName"), str):
                ns_name = ns["ldhName"].strip().lower().rstrip(".")
                if ns_name:
                    facts.append(FactDraft(attribute="whois.nameserver", value=ns_name[:253], entity_kind=entity_kind, entity_name=target))

        # Entities (registrar / registrant / network org)
        for ent in data.get("entities") or []:
            if not isinstance(ent, dict):
                continue
            roles = [r.lower() for r in (ent.get("roles") or []) if isinstance(r, str)]
            name = _vcard_fn(ent.get("vcardArray")) or ent.get("handle")
            if isinstance(name, str) and name.strip():
                clean_name = name.strip()[:200]
                if "registrar" in roles and not is_ip:
                    facts.append(FactDraft(attribute="whois.registrar", value=clean_name, entity_kind=entity_kind, entity_name=target))
                elif is_ip and any(r in roles for r in ("registrant", "administrative", "technical", "noc")):
                    facts.append(FactDraft(attribute="host.org", value=clean_name, entity_kind=entity_kind, entity_name=target))

        if is_ip:
            if isinstance(data.get("name"), str) and data["name"].strip():
                facts.append(FactDraft(attribute="host.network_name", value=data["name"].strip()[:200], entity_kind="ip", entity_name=target))
            if isinstance(data.get("country"), str) and data["country"].strip():
                facts.append(FactDraft(attribute="host.country", value=data["country"].strip()[:32], entity_kind="ip", entity_name=target))
            for cidr in (data.get("cidr0_cidrs") or [])[:10]:
                if isinstance(cidr, dict):
                    prefix = cidr.get("v4prefix") or cidr.get("v6prefix")
                    length = cidr.get("length")
                    if prefix and length is not None:
                        facts.append(FactDraft(attribute="host.cidr", value=f"{prefix}/{length}", entity_kind="ip", entity_name=target))

        # Deduplicate while preserving order
        seen = set()
        unique: list[FactDraft] = []
        for f in facts:
            key = (f.attribute, f.value, f.entity_name)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


def _vcard_fn(vcard_array) -> str | None:
    if not isinstance(vcard_array, list) or len(vcard_array) < 2 or not isinstance(vcard_array[1], list):
        return None
    for row in vcard_array[1]:
        if isinstance(row, list) and len(row) >= 4 and row[0] in ("fn", "org") and isinstance(row[3], str) and row[3].strip():
            return row[3].strip()
    return None
