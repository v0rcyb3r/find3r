"""Direction: turn Priority Intelligence Requirements into a collection plan.

This is the phase the audited code had no equivalent of. Without it, "enter a
domain and get everything" is a scanner: collection has no objective, the
budget has no priority order, and a run cannot tell you what it failed to
learn.

A PIR names the attributes that would answer it. The planner asks the
registry which adapters produce those attributes, orders them free-first, and
reports any requirement nothing in the registry can satisfy. Deterministic,
free, and a table test — an LLM planner buys nothing here and would be the
one cost paid on every single run.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Iterable, Optional
from uuid import uuid4

from neesha.adapters import registry
from neesha.adapters.base import AdapterError, Request

# Named requirement sets an analyst can ask for by name. Each entry is
# (question, attributes that would answer it).
PIR_TEMPLATES: dict[str, list[tuple[str, frozenset[str]]]] = {
    "email-public-presence": [
        ("What mail provider, deliverability, and public email OSINT signals exist for this address?", frozenset({"public.email.provider", "public.email.deliverable_mx"})),
        ("Which public GitHub commit observations explicitly match this exact email?", frozenset({"public.email.github"})),
        ("Which public Gravatar profile observations match the email hash?", frozenset({"public.profile.gravatar"})),
        ("Which public email reputation observations are available?", frozenset({"public.email.emailrep"})),
    ],
    "email-account-presence": [
        ("On which services does an account exist for this exact email?",
         frozenset({"public.account"})),
    ],
    "username-account-presence": [
        ("On which services does an account exist for this exact username?",
         frozenset({"public.account"})),
    ],
    "phone-public-presence": [
        ("What E.164 numbering plan, carrier/region, and public web mentions exist for this phone number?",
         frozenset({"public.phone", "public.account"})),
    ],
    "person-public-presence": [
        ("What public profiles, organizations, PGP keys, and biographical records match this person name?",
         frozenset({"public.person", "public.account", "public.profile"})),
    ],
    "breach-exposure": [
        ("What breach datasets, credential-exposure counts, and correlated records are reported in DeHashed or Intelligence X?",
         frozenset({"dehashed.breach"})),
    ],
    "company-contacts": [
        ("Which business emails and phone numbers does the company publish?",
         frozenset({"company.business_email", "company.business_phone"})),
        ("Which named professional roles are published by the company?",
         frozenset({"person.role"})),
    ],
    "email-posture": [
        ("What SPF and DMARC policies are published?",
         frozenset({"email.spf.qualifier", "email.dmarc.policy"})),
        ("Which public addresses and mail servers are observed?",
         frozenset({"dns.a", "dns.mx"})),
    ],
    "public-history": [
        ("Which URLs appear in public archives and existing scan records?",
         frozenset({"web.archive.url", "web.observed.url"})),
    ],
    "web-response": [
        ("What HTTPS and security headers are observed on the company website?",
         frozenset({"http.status", "tls.connection.validated", "http.security_header", "security_txt.contact"})),
    ],
    "tool-discovery": [
        ("Which hostnames do installed passive discovery tools report?",
         frozenset({"discovery.subdomain"})),
    ],
    "whois-registration": [
        ("What domain registration and lifecycle records are published in RDAP/WHOIS?",
         frozenset({"whois.registrar", "whois.created", "whois.expires"})),
    ],
    "ip-infrastructure": [
        ("What network ownership, open ports, CPEs, and CVEs are observed for this IP?",
         frozenset({"host.port", "host.cpe", "host.vuln", "host.org", "host.network_name", "bgp.prefix"})),
    ],
    "attack-surface": [
        (
            "What hostnames does this company expose?",
            frozenset({"dns.subdomain"}),
        ),
        (
            "Who issues their certificates?",
            frozenset({"tls.ct.issuer"}),
        ),
    ],
    "who-to-contact": [
        (
            "What is their business email pattern?",
            frozenset({"email.pattern"}),
        ),
        (
            "Which named business contacts can we identify, and in what roles?",
            frozenset({"person.business_email", "person.role"}),
        ),
    ],
    "email-security-fit": [
        (
            "Is email authentication enforced on this domain?",
            frozenset({"email.dmarc.policy", "email.spf.qualifier"}),
        ),
        (
            "What is their email pattern, for a spoofing demonstration?",
            frozenset({"email.pattern"}),
        ),
    ],
}


@dataclass
class PIR:
    question: str
    answers_attributes: frozenset[str]
    template: Optional[str] = None
    id: str = field(default_factory=lambda: uuid4().hex)
    status: str = "open"
    answer: Optional[str] = None
    gap_reason: Optional[str] = None
    fact_ids: list[str] = field(default_factory=list)


@dataclass
class Step:
    adapter_name: str
    request: Request
    tier: str
    estimated_usd: Decimal
    serves: list[str] = field(default_factory=list)  # PIR ids


@dataclass
class Plan:
    steps: list[Step] = field(default_factory=list)
    pirs: list[PIR] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)

    @property
    def estimated_total_usd(self) -> Decimal:
        return sum((s.estimated_usd for s in self.steps), Decimal("0"))

    @property
    def unanswerable(self) -> list[PIR]:
        return [p for p in self.pirs if p.status == "unanswerable"]


def expand_templates(names: Iterable[str]) -> list[PIR]:
    """Build PIRs from template names, rejecting unknown ones loudly."""
    pirs: list[PIR] = []
    for name in names:
        template = PIR_TEMPLATES.get(name)
        if template is None:
            raise KeyError(
                f"unknown PIR template {name!r}; "
                f"known: {', '.join(sorted(PIR_TEMPLATES))}"
            )
        for question, attributes in template:
            pirs.append(
                PIR(question=question, answers_attributes=attributes, template=name)
            )
    return pirs


def build_plan(
    pirs: list[PIR],
    subject: str,
    *,
    entity_kind: str = "domain",
    tiers: Optional[set[str]] = None,
    sources: Optional[set[str]] = None,
) -> Plan:
    """Select the adapters that can answer these requirements.

    One step per adapter even when it serves several requirements: paying
    twice for one call to satisfy two questions would be exactly the waste
    the ledger exists to prevent.
    """
    available = registry.produced_attributes(tiers, sources)
    steps: dict[str, Step] = {}
    skipped: dict[str, dict] = {}

    for pir in pirs:
        candidates = [cls for cls in registry.for_attributes(pir.answers_attributes, tiers, sources)
                      if entity_kind in cls.accepts]
        if not candidates:
            pir.status = "unanswerable"
            missing = sorted(
                a
                for a in pir.answers_attributes
                if not any(a == p or a.startswith(p + ".") for p in available)
            )
            pir.gap_reason = (
                "no adapter in the registry produces "
                + (", ".join(missing) or "these attributes")
            )
            continue

        request = Request(entity_kind=entity_kind, value=subject)
        for cls in candidates:
            step = steps.get(cls.name)
            if step is None:
                try:
                    estimate = Decimal(str(cls().estimate_cost(request).usd))
                except (AdapterError, ValueError):
                    skipped[cls.name] = {"adapter": cls.name, "reason": "Source cost is not configured or cannot be estimated."}
                    pir.gap_reason = skipped[cls.name]["reason"]
                    continue
                step = Step(
                    adapter_name=cls.name,
                    request=request,
                    tier=cls.tier,
                    estimated_usd=estimate,
                )
                steps[cls.name] = step
            if pir.id not in step.serves:
                step.serves.append(pir.id)

    ordered = sorted(
        steps.values(),
        key=lambda s: (registry.TIER_ORDER.get(s.tier, 9), s.estimated_usd, s.adapter_name),
    )
    return Plan(steps=ordered, pirs=pirs, skipped=list(skipped.values()))
