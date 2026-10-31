"""Posture collector: DNS, email auth, TLS, HTTP headers, DNSSEC.

All collection is passive and cross-resolver validated where the spec
requires it (SPF/DMARC TXT via system + Cloudflare DoH + Google DoH).
Wildcard DNS is detected so DKIM absence is not misread as a gap.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from neesha.collectors.base import Collector
from neesha.collectors.network import fetch_http, get_tls_cert
from neesha.evidence.models import Confidence, utcnow
from neesha.posture.brief import Check, PostureBrief
from neesha.posture.facts import (
    DNSResult,
    DKIMResult,
    DMARCResult,
    DNSSECResult,
    HTTPResult,
    MTASTSResult,
    SPFResult,
    TLSRPTResult,
    TLSResult,
)
from neesha.posture.grader import grade_posture
from neesha.posture.parsers import parse_dmarc, parse_mtasts, parse_spf, parse_tlsrpt
from neesha.resolvers.dns import DoHResolver, SystemResolver, dnssec_status

DEFAULT_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail",
    "dkim", "mandrill", "amazonses", "zoho", "protonmail", "sendgrid", "mailgun",
]


def normalize_domain(value: str) -> str:
    value = value.strip().lower()
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    value = value.split("/")[0].split(":")[0].rstrip(".")
    return value


@dataclass
class CollectedFacts:
    dns: DNSResult
    spf: SPFResult
    dmarc: DMARCResult
    dkim: DKIMResult
    mtasts: MTASTSResult
    tlsrpt: TLSRPTResult
    tls: TLSResult
    http: HTTPResult
    dnssec: DNSSECResult
    wildcard: bool
    unstable_dns: bool
    domain_txt_sets: dict[str, list[str]]
    dmarc_txt_sets: dict[str, list[str]]
    dkim_records: dict[str, str] = field(default_factory=dict)


class PostureCollector(Collector):
    name = "posture"
    agent = "posture"
    SOURCES = ["system-dns", "cloudflare-doh", "google-doh", "tls", "http"]
    _RESOLVER_ORDER = ("system", "cloudflare-doh", "google-doh")

    def __init__(self, scope, store, target: str, selectors: Optional[list[str]] = None, audit=None):
        super().__init__(scope, store, target, audit=audit)
        self.target = normalize_domain(target)
        self.system = SystemResolver()
        self.cloudflare = DoHResolver("cloudflare-doh", "https://cloudflare-dns.com/dns-query")
        self.google = DoHResolver("google-doh", "https://dns.google/resolve")
        self.selectors = selectors or DEFAULT_SELECTORS
        self._evidences: list = []
        self._checks: list[Check] = []

    # ---- orchestration -----------------------------------------------------

    def run(self) -> tuple[list, PostureBrief]:
        for source in self.SOURCES:
            self.authorize(source)
        facts = self._collect_facts()
        self._emit_all(facts)
        brief = self._build_brief(facts)
        return self._evidences, brief

    # ---- collection (no evidence yet) -------------------------------------

    def _collect_facts(self) -> CollectedFacts:
        dns = DNSResult()
        for rtype, attr in [("A", "a"), ("AAAA", "aaaa"), ("MX", "mx"), ("NS", "ns"), ("SOA", "soa"), ("CAA", "caa")]:
            records, _ = self._resolve(self.target, rtype)
            setattr(dns, attr, records)

        domain_txt_sets = self._txt_sets(self.target)
        dmarc_txt_sets = self._txt_sets(f"_dmarc.{self.target}")
        wildcard = self._detect_wildcard()
        unstable_dns = self._disagree(domain_txt_sets) or self._disagree(dmarc_txt_sets)

        spf = parse_spf(self._pick(domain_txt_sets), unstable=self._disagree(domain_txt_sets))
        dmarc = parse_dmarc(self._pick(dmarc_txt_sets), unstable=self._disagree(dmarc_txt_sets))

        dkim, dkim_records = self._collect_dkim(wildcard)
        mtasts_txt, _ = self._resolve(f"_mta-sts.{self.target}", "TXT")
        mtasts = parse_mtasts(mtasts_txt)
        tlsrpt_txt, _ = self._resolve(f"_smtp._tls.{self.target}", "TXT")
        tlsrpt = parse_tlsrpt(tlsrpt_txt)

        tls = self._collect_tls()
        http = self._collect_http()
        # A successful TLS handshake means HTTPS is available even when the
        # homepage GET returned an HTTP error status (which urllib surfaces
        # as an exception). Don't claim "no HTTPS" off a failed page fetch.
        if tls.connected:
            http.https_available = True

        return CollectedFacts(
            dns=dns,
            spf=spf,
            dmarc=dmarc,
            dkim=dkim,
            mtasts=mtasts,
            tlsrpt=tlsrpt,
            tls=tls,
            http=http,
            dnssec=self._collect_dnssec(),
            wildcard=wildcard,
            unstable_dns=unstable_dns,
            domain_txt_sets=domain_txt_sets,
            dmarc_txt_sets=dmarc_txt_sets,
            dkim_records=dkim_records,
        )

    def _resolve(self, name: str, rtype: str) -> tuple[list[str], str]:
        for resolver in (self.system, self.cloudflare, self.google):
            result = resolver.query(name, rtype)
            if result.status == "ok":
                return [rec.value for rec in result.records], resolver.name
            if result.status in ("nxdomain", "noerror-nodata"):
                return [], resolver.name
        return [], "none"

    def _txt_sets(self, name: str) -> dict[str, list[str]]:
        sets: dict[str, list[str]] = {}
        for resolver in (self.system, self.cloudflare, self.google):
            result = resolver.query(name, "TXT")
            if result.status == "ok":
                sets[resolver.name] = [rec.value for rec in result.records]
        return sets

    @staticmethod
    def _pick(sets: dict[str, list[str]], order: tuple = _RESOLVER_ORDER) -> list[str]:
        for name in order:
            if sets.get(name):
                return sets[name]
        return []

    @staticmethod
    def _disagree(sets: dict[str, list[str]]) -> bool:
        nonempty = [frozenset(v) for v in sets.values() if v]
        return len(set(nonempty)) > 1 if len(nonempty) >= 2 else False

    def _detect_wildcard(self) -> bool:
        probe = f"neesha-{uuid.uuid4().hex[:12]}.{self.target}"
        for resolver in (self.system, self.cloudflare):
            result = resolver.query(probe, "A")
            if result.status == "ok" and result.records:
                return True
        return False

    def _collect_dkim(self, wildcard: bool) -> tuple[DKIMResult, dict[str, str]]:
        found: dict[str, str] = {}
        for selector in self.selectors:
            records, _ = self._resolve(f"{selector}._domainkey.{self.target}", "TXT")
            if records:
                found[selector] = records[0]
        dkim = DKIMResult(
            selectors_found=sorted(found),
            selectors_checked=list(self.selectors),
            wildcard=wildcard,
        )
        return dkim, found

    def _collect_tls(self) -> TLSResult:
        try:
            cert = get_tls_cert(self.target)
        except Exception as exc:  # noqa: BLE001 - connection errors are collection results
            return TLSResult(connected=False, error=str(exc))
        not_after = cert.get("not_after")
        days = None
        if not_after is not None:
            days = (not_after - datetime.now(timezone.utc)).days
        return TLSResult(
            connected=True,
            issuer=cert.get("issuer"),
            not_after=not_after,
            san=cert.get("san", []),
            days_remaining=days,
        )

    def _collect_http(self) -> HTTPResult:
        https_ok = False
        try:
            resp = fetch_http(f"https://{self.target}/")
            https_ok = True
        except Exception as https_exc:  # noqa: BLE001
            try:
                resp = fetch_http(f"http://{self.target}/")
            except Exception as http_exc:  # noqa: BLE001
                return HTTPResult(fetched=False, error=f"https: {https_exc}; http: {http_exc}")
        headers = resp["headers"]
        return HTTPResult(
            fetched=True,
            https_available=https_ok or resp["final_url"].startswith("https://"),
            final_url=resp["final_url"],
            status=resp["status"],
            hsts=headers.get("strict-transport-security"),
            csp="content-security-policy" in headers,
            x_frame_options=headers.get("x-frame-options"),
            x_content_type_options=headers.get("x-content-type-options"),
            referrer_policy="referrer-policy" in headers,
            permissions_policy="permissions-policy" in headers,
        )

    def _collect_dnssec(self) -> DNSSECResult:
        status, ad, keys = dnssec_status([self.cloudflare, self.google], self.target)
        return DNSSECResult(status=status, ad=ad, keys_present=keys)

    # ---- evidence + checks -------------------------------------------------

    def _emit(
        self,
        *,
        name: str,
        category: str,
        status: str,
        detail: str,
        records: list[str],
        claim: str,
        source_type: str,
        source_url: Optional[str] = None,
        confidence: Confidence = Confidence.HIGH,
    ) -> str:
        evidence = self.record(
            claim=claim,
            source_type=source_type,
            source_url=source_url,
            confidence=confidence,
        )
        self._evidences.append(evidence)
        self._checks.append(
            Check(
                name=name,
                category=category,
                status=status,
                detail=detail,
                records=records,
                evidence_ids=[evidence.evidence_id],
            )
        )
        return evidence.evidence_id

    def _emit_all(self, facts: CollectedFacts) -> None:
        d = self.target
        for rtype, attr in [("A", "a"), ("AAAA", "aaaa"), ("MX", "mx"), ("NS", "ns"), ("SOA", "soa"), ("CAA", "caa")]:
            records = getattr(facts.dns, attr)
            self._emit(
                name=f"DNS {rtype}",
                category="dns",
                status="ok" if records else "info",
                detail=f"{rtype} records: {', '.join(records) or 'none'}",
                records=records,
                claim=f"{rtype} records for {d}: {', '.join(records) or 'none'}",
                source_type="dns",
                source_url=f"https://dns.google/resolve?name={d}&type={rtype}",
            )

        self._emit(
            name="Wildcard DNS",
            category="dns",
            status="info" if facts.wildcard else "ok",
            detail=(
                f"Wildcard {'detected' if facts.wildcard else 'not detected'}; "
                f"DKIM absence {'is not a misconfiguration signal' if facts.wildcard else 'is a gap'}"
            ),
            records=[f"wildcard={facts.wildcard}"],
            claim=f"Wildcard DNS for {d}: {'detected' if facts.wildcard else 'not detected'}",
            source_type="dns",
            source_url=f"https://dns.google/resolve?name=neesha-probe.{d}&type=A",
        )

        self._emit_spf(facts)
        self._emit_dmarc(facts)
        self._emit_dkim(facts)

        self._emit(
            name="MTA-STS",
            category="email_auth",
            status="ok" if facts.mtasts.present else "gap",
            detail=f"MTA-STS policy {'present' if facts.mtasts.present else 'absent'}",
            records=[facts.mtasts.record] if facts.mtasts.record else [],
            claim=f"MTA-STS for {d}: {'present' if facts.mtasts.present else 'absent'}",
            source_type="dns",
            source_url=f"https://dns.google/resolve?name=_mta-sts.{d}&type=TXT",
        )
        self._emit(
            name="TLS-RPT",
            category="email_auth",
            status="ok" if facts.tlsrpt.present else "info",
            detail=f"TLS-RPT reporting {'present' if facts.tlsrpt.present else 'absent'}",
            records=[facts.tlsrpt.record] if facts.tlsrpt.record else [],
            claim=f"TLS-RPT for {d}: {'present' if facts.tlsrpt.present else 'absent'}",
            source_type="dns",
            source_url=f"https://dns.google/resolve?name=_smtp._tls.{d}&type=TXT",
        )

        self._emit(
            name="DNSSEC",
            category="dnssec",
            status="ok" if facts.dnssec.status == "validated" else ("warn" if facts.dnssec.status == "signed-not-validated" else "gap"),
            detail=f"DNSSEC status: {facts.dnssec.status} (AD={facts.dnssec.ad}, keys={facts.dnssec.keys_present})",
            records=[facts.dnssec.status],
            claim=f"DNSSEC for {d}: {facts.dnssec.status}",
            source_type="dns",
            source_url=f"https://dns.google/resolve?name={d}&type=DNSKEY",
        )

        self._emit_tls(facts)
        self._emit_http(facts)

    def _emit_spf(self, facts: CollectedFacts) -> None:
        spf = facts.spf
        records = [f"{res}: {', '.join(vals) or 'none'}" for res, vals in facts.domain_txt_sets.items()]
        status = "unstable" if spf.unstable else ("ok" if spf.present and spf.qualifier == "-all" else ("warn" if spf.present else "gap"))
        detail = (
            f"SPF {'present' if spf.present else 'absent'}; qualifier {spf.qualifier or 'n/a'}"
            + ("; UNSTABLE across resolvers" if spf.unstable else "")
        )
        self._emit(
            name="SPF",
            category="email_auth",
            status=status,
            detail=detail,
            records=records,
            claim=f"SPF for {self.target}: {spf.record or 'absent'} (qualifier {spf.qualifier or 'n/a'})",
            source_type="dns",
            source_url=f"https://dns.google/resolve?name={self.target}&type=TXT",
        )

    def _emit_dmarc(self, facts: CollectedFacts) -> None:
        dmarc = facts.dmarc
        records = [f"{res}: {', '.join(vals) or 'none'}" for res, vals in facts.dmarc_txt_sets.items()]
        status = "unstable" if dmarc.unstable else ("ok" if dmarc.present and dmarc.policy == "reject" else ("warn" if dmarc.present else "gap"))
        detail = (
            f"DMARC {'present' if dmarc.present else 'absent'}; p={dmarc.policy or 'n/a'}"
            + ("; UNSTABLE across resolvers" if dmarc.unstable else "")
        )
        self._emit(
            name="DMARC",
            category="email_auth",
            status=status,
            detail=detail,
            records=records,
            claim=f"DMARC for {self.target}: {dmarc.record or 'absent'} (p={dmarc.policy or 'n/a'})",
            source_type="dns",
            source_url=f"https://dns.google/resolve?name=_dmarc.{self.target}&type=TXT",
        )

    def _emit_dkim(self, facts: CollectedFacts) -> None:
        dkim = facts.dkim
        status = "ok" if dkim.selectors_found else ("neutral" if dkim.wildcard else "gap")
        records = [f"{sel}: {val}" for sel, val in facts.dkim_records.items()]
        detail = (
            f"Selectors found: {', '.join(dkim.selectors_found) or 'none'} "
            f"of {len(dkim.selectors_checked)} checked (selector coverage limited)"
        )
        self._emit(
            name="DKIM",
            category="email_auth",
            status=status,
            detail=detail,
            records=records,
            claim=f"DKIM for {self.target}: found {', '.join(dkim.selectors_found) or 'none'} of {len(dkim.selectors_checked)} checked selectors; wildcard={dkim.wildcard}",
            source_type="dns",
            source_url=f"https://dns.google/resolve?name=selector._domainkey.{self.target}&type=TXT",
        )

    def _emit_tls(self, facts: CollectedFacts) -> None:
        tls = facts.tls
        if not tls.connected:
            self._emit(
                name="TLS certificate",
                category="tls",
                status="error",
                detail=f"TLS handshake failed: {tls.error}",
                records=[],
                claim=f"TLS certificate for {self.target}: could not connect ({tls.error})",
                source_type="tls",
                source_url=f"https://{self.target}:443/",
            )
            return
        expiry = tls.not_after.isoformat() if tls.not_after else "unknown"
        days = tls.days_remaining
        status = "ok" if days is not None and days > 30 else ("warn" if days is not None and days > 0 else "gap")
        detail = f"Issuer: {tls.issuer or 'unknown'}; expires {expiry} ({days} days); SANs: {', '.join(tls.san) or 'none'}"
        self._emit(
            name="TLS certificate",
            category="tls",
            status=status,
            detail=detail,
            records=[f"issuer={tls.issuer}", f"notAfter={expiry}", f"san={tls.san}"],
            claim=f"TLS certificate for {self.target}: issuer {tls.issuer or 'unknown'}, expires {expiry} ({days} days remaining)",
            source_type="tls",
            source_url=f"https://{self.target}:443/",
        )

    def _emit_http(self, facts: CollectedFacts) -> None:
        http = facts.http
        if not http.fetched:
            self._emit(
                name="HTTP",
                category="web_headers",
                status="error",
                detail=f"HTTP fetch failed: {http.error}",
                records=[],
                claim=f"HTTP headers for {self.target}: fetch failed ({http.error})",
                source_type="http",
                source_url=f"https://{self.target}/",
            )
            return
        checks = [
            ("HSTS", http.hsts or "absent", "ok" if http.hsts else "gap"),
            ("Content-Security-Policy", "present" if http.csp else "absent", "ok" if http.csp else "gap"),
            ("X-Frame-Options", http.x_frame_options or "absent", "ok" if http.x_frame_options else "gap"),
            ("X-Content-Type-Options", http.x_content_type_options or "absent", "ok" if http.x_content_type_options else "gap"),
            ("Referrer-Policy", "present" if http.referrer_policy else "absent", "ok" if http.referrer_policy else "gap"),
            ("Permissions-Policy", "present" if http.permissions_policy else "absent", "ok" if http.permissions_policy else "gap"),
        ]
        for name, value, status in checks:
            self._emit(
                name=name,
                category="web_headers",
                status=status,
                detail=f"{name}: {value}",
                records=[value],
                claim=f"{name} for {self.target}: {value}",
                source_type="http",
                source_url=http.final_url,
            )
        if not http.https_available:
            self._emit(
                name="HTTPS",
                category="web_headers",
                status="gap",
                detail="Site reachable only over plaintext HTTP",
                records=[],
                claim=f"HTTPS for {self.target}: not available (plaintext HTTP only)",
                source_type="http",
                source_url=http.final_url,
            )

    def _build_brief(self, facts: CollectedFacts) -> PostureBrief:
        overall, categories, triggers = grade_posture(
            facts.spf, facts.dmarc, facts.dkim, facts.tls, facts.http, facts.dnssec, facts.unstable_dns
        )
        flags = []
        if facts.wildcard:
            flags.append("wildcard-dns")
        if facts.unstable_dns:
            flags.append("unstable-dns")
        return PostureBrief(
            target=self.target,
            collected_at=utcnow(),
            overall=overall,
            categories=categories,
            checks=self._checks,
            triggers=triggers,
            flags=flags,
            evidence_count=len(self._evidences),
        )
