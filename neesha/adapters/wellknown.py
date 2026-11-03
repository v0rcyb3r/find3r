"""RFC 9116 /.well-known/security.txt and /robots.txt passive disclosure posture adapter."""
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


def _domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in labels
    ):
        raise AdapterError("security-txt requires a valid public domain")
    return domain


def _assert_global_resolution(domain: str) -> None:
    try:
        infos = socket.getaddrinfo(domain, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except Exception as exc:
        raise AdapterError(f"Could not resolve {domain}") from exc
    if not infos:
        raise AdapterError(f"No address records for {domain}")
    for info in infos:
        addr = info[4][0]
        ip_obj = ipaddress.ip_address(addr)
        if not ip_obj.is_global:
            raise AdapterError(f"Refusing non-global address for {domain}")


class SecurityTxtAdapter(BaseAdapter):
    name: ClassVar[str] = "security-txt"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = False
    collection_mode: ClassVar[str] = "passive"
    source_type: ClassVar[str] = "first_party"
    description: ClassVar[str] = "RFC 9116 /.well-known/security.txt & /robots.txt disclosure policy, security contacts, and route posture"
    produces: ClassVar[frozenset[str]] = frozenset({
        "security_txt.contact",
        "security_txt.policy",
        "security_txt.encryption",
        "security_txt.acknowledgments",
        "security_txt.canonical",
        "security_txt.expires",
        "web.robots_disallow",
        "web.sitemap_url",
    })
    accepts: ClassVar[frozenset[str]] = frozenset({"domain", "company"})
    retention_days: ClassVar[int] = 14
    max_payload_bytes: ClassVar[int] = 128 * 1024
    timeout: ClassVar[int] = 10

    def search(self, request: Request) -> list[Reference]:
        domain = _domain(request.value)
        return [
            Reference(
                url=f"https://{domain}/.well-known/security.txt",
                origin_url=f"https://{domain}/",
                label=domain,
                params={"domain": domain},
            )
        ]

    def _safe_get_text(self, url: str) -> str:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=_default_context()),
            _NoRedirect(),
        )
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Find3r/0.2", "Accept": "text/plain"},
        )
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return ""
                ctype = (resp.headers.get("Content-Type") or "").lower()
                if "html" in ctype:
                    return ""
                raw = resp.read(self.max_payload_bytes + 1)
                if len(raw) > self.max_payload_bytes:
                    return ""
                return raw.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def fetch(self, reference: Reference) -> RawResult:
        domain = _domain((reference.params or {}).get("domain") or reference.label or "")
        _assert_global_resolution(domain)
        sec_txt = self._safe_get_text(f"https://{domain}/.well-known/security.txt")
        if not sec_txt:
            sec_txt = self._safe_get_text(f"https://{domain}/security.txt")
        robots_txt = self._safe_get_text(f"https://{domain}/robots.txt")
        payload = json.dumps({
            "domain": domain,
            "security_txt": sec_txt[:65536],
            "robots_txt": robots_txt[:65536],
        }).encode("utf-8")
        return RawResult(
            payload=payload,
            request_url=reference.url,
            origin_url=reference.origin_url,
            http_status=200 if (sec_txt or robots_txt) else 404,
            content_type="application/json",
            collected_at=datetime.now(timezone.utc),
        )

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        if raw.http_status == 404 or raw.payload == b"{}":
            return []
        try:
            data = json.loads(raw.payload)
        except (ValueError, UnicodeError) as exc:
            raise AdapterError("security-txt returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise AdapterError("security-txt returned unexpected response")

        domain = _domain(str(data.get("domain") or request.value))
        sec_txt = str(data.get("security_txt") or "")
        robots_txt = str(data.get("robots_txt") or "")

        field_map = {
            "contact": "security_txt.contact",
            "policy": "security_txt.policy",
            "encryption": "security_txt.encryption",
            "acknowledgments": "security_txt.acknowledgments",
            "canonical": "security_txt.canonical",
            "expires": "security_txt.expires",
        }
        seen: set[tuple[str, str]] = set()
        facts: list[FactDraft] = []

        for line in sec_txt.splitlines()[:200]:
            s = line.strip()
            if not s or s.startswith("#") or ":" not in s:
                continue
            k, v = s.split(":", 1)
            attr = field_map.get(k.strip().lower())
            val = v.strip()[:240]
            if attr and val and (attr, val) not in seen:
                seen.add((attr, val))
                facts.append(FactDraft(attribute=attr, value=val, entity_kind="domain", entity_name=domain))

        disallow_count = 0
        for line in robots_txt.splitlines()[:300]:
            s = line.strip()
            if not s or s.startswith("#") or ":" not in s:
                continue
            k, v = s.split(":", 1)
            key_low = k.strip().lower()
            val = v.strip()[:200]
            if not val:
                continue
            if key_low == "disallow" and val != "/" and disallow_count < 25:
                if ("web.robots_disallow", val) not in seen:
                    seen.add(("web.robots_disallow", val))
                    disallow_count += 1
                    facts.append(FactDraft(attribute="web.robots_disallow", value=val, entity_kind="domain", entity_name=domain))
            elif key_low == "sitemap" and val.startswith(("http://", "https://")):
                parsed = urllib.parse.urlsplit(val)
                if not parsed.username and not parsed.password and ("web.sitemap_url", val) not in seen:
                    seen.add(("web.sitemap_url", val))
                    facts.append(FactDraft(attribute="web.sitemap_url", value=val, entity_kind="domain", entity_name=domain))

        return facts
