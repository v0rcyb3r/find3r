"""Keyless Phone Number OSINT adapter: ITU-T E.164 parsing, NANPA geographic/carrier telemetry, and public web mentions."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any, ClassVar
import urllib.error
import urllib.parse
import urllib.request

from neesha.adapters.base import AdapterError, BaseAdapter, FactDraft, RawResult, Reference, Request
from neesha.collectors.network import _default_context
from neesha.resolve.intake import resolve_seed

COUNTRY_CALLING_CODES: tuple[tuple[str, str, str], ...] = (
    ("1", "United States / Canada (NANPA)", "America/New_York"),
    ("44", "United Kingdom", "Europe/London"),
    ("33", "France", "Europe/Paris"),
    ("49", "Germany", "Europe/Berlin"),
    ("34", "Spain", "Europe/Madrid"),
    ("39", "Italy", "Europe/Rome"),
    ("31", "Netherlands", "Europe/Amsterdam"),
    ("41", "Switzerland", "Europe/Zurich"),
    ("46", "Sweden", "Europe/Stockholm"),
    ("47", "Norway", "Europe/Oslo"),
    ("48", "Poland", "Europe/Warsaw"),
    ("61", "Australia", "Australia/Sydney"),
    ("64", "New Zealand", "Pacific/Auckland"),
    ("65", "Singapore", "Asia/Singapore"),
    ("81", "Japan", "Asia/Tokyo"),
    ("82", "South Korea", "Asia/Seoul"),
    ("86", "China", "Asia/Shanghai"),
    ("91", "India", "Asia/Kolkata"),
    ("55", "Brazil", "America/Sao_Paulo"),
    ("52", "Mexico", "America/Mexico_City"),
    ("971", "United Arab Emirates", "Asia/Dubai"),
    ("972", "Israel", "Asia/Jerusalem"),
    ("27", "South Africa", "Africa/Johannesburg"),
)

NANPA_AREA_CODES: dict[str, tuple[str, str]] = {
    "201": ("New Jersey (Jersey City / Hackensack)", "America/New_York"),
    "202": ("Washington, D.C.", "America/New_York"),
    "203": ("Connecticut (Bridgeport / New Haven)", "America/New_York"),
    "206": ("Washington (Seattle)", "America/Los_Angeles"),
    "212": ("New York (Manhattan)", "America/New_York"),
    "213": ("California (Los Angeles)", "America/Los_Angeles"),
    "214": ("Texas (Dallas)", "America/Chicago"),
    "215": ("Pennsylvania (Philadelphia)", "America/New_York"),
    "301": ("Maryland (Silver Spring / Frederick)", "America/New_York"),
    "302": ("Delaware", "America/New_York"),
    "303": ("Colorado (Denver / Boulder)", "America/Denver"),
    "305": ("Florida (Miami)", "America/New_York"),
    "310": ("California (Santa Monica / Beverly Hills)", "America/Los_Angeles"),
    "312": ("Illinois (Chicago Downtown)", "America/Chicago"),
    "313": ("Michigan (Detroit)", "America/Detroit"),
    "347": ("New York (NYC Outer Boroughs)", "America/New_York"),
    "404": ("Georgia (Atlanta)", "America/New_York"),
    "408": ("California (San Jose / Silicon Valley)", "America/Los_Angeles"),
    "415": ("California (San Francisco / Marin)", "America/Los_Angeles"),
    "416": ("Ontario (Toronto)", "America/Toronto"),
    "425": ("Washington (Bellevue / Redmond)", "America/Los_Angeles"),
    "469": ("Texas (Dallas Metro)", "America/Chicago"),
    "510": ("California (Oakland / East Bay)", "America/Los_Angeles"),
    "512": ("Texas (Austin)", "America/Chicago"),
    "514": ("Quebec (Montreal)", "America/Toronto"),
    "602": ("Arizona (Phoenix)", "America/Phoenix"),
    "604": ("British Columbia (Vancouver)", "America/Vancouver"),
    "617": ("Massachusetts (Boston / Cambridge)", "America/New_York"),
    "646": ("New York (Manhattan)", "America/New_York"),
    "650": ("California (Palo Alto / San Mateo)", "America/Los_Angeles"),
    "702": ("Nevada (Las Vegas)", "America/Los_Angeles"),
    "703": ("Virginia (Northern Virginia / Arlington)", "America/New_York"),
    "713": ("Texas (Houston)", "America/Chicago"),
    "718": ("New York (Outer Boroughs)", "America/New_York"),
    "786": ("Florida (Miami-Dade)", "America/New_York"),
    "800": ("NANPA Toll-Free Service", "UTC"),
    "833": ("NANPA Toll-Free Service", "UTC"),
    "844": ("NANPA Toll-Free Service", "UTC"),
    "855": ("NANPA Toll-Free Service", "UTC"),
    "866": ("NANPA Toll-Free Service", "UTC"),
    "877": ("NANPA Toll-Free Service", "UTC"),
    "888": ("NANPA Toll-Free Service", "UTC"),
    "917": ("New York (NYC Mobile & Boroughs)", "America/New_York"),
    "929": ("New York (NYC Boroughs)", "America/New_York"),
    "949": ("California (Irvine / Orange County)", "America/Los_Angeles"),
}


class PhoneOsintAdapter(BaseAdapter):
    name: ClassVar[str] = "phone-osint"
    tier: ClassVar[str] = "A"
    default_enabled: ClassVar[bool] = True
    collection_mode: ClassVar[str] = "third_party_passive"
    source_type: ClassVar[str] = "osint"
    description: ClassVar[str] = (
        "Keyless phone OSINT: ITU-T E.164 numbering plan analysis, NANPA region/timezone mapping, "
        "line classification, and public repository/web footprint search"
    )
    produces: ClassVar[frozenset[str]] = frozenset({"public.phone", "public.account"})
    accepts: ClassVar[frozenset[str]] = frozenset({"phone"})
    retention_days: ClassVar[int] = 14
    timeout: ClassVar[int] = 8

    def search(self, request: Request) -> list[Reference]:
        normalized = resolve_seed(request.value, "phone")["normalized"]
        return [
            Reference(
                url="osint://phone-osint/" + urllib.parse.quote(normalized, safe="+"),
                origin_url="https://api.github.com/",
                label=normalized,
            )
        ]

    def _parse_numbering_plan(self, normalized: str) -> dict[str, Any]:
        digits = re.sub(r"[^0-9]", "", normalized)
        has_plus = normalized.startswith("+")
        if not has_plus and len(digits) == 10:
            # Default 10-digit NANPA assumption when no leading + is supplied
            digits = "1" + digits
            e164 = "+" + digits
        else:
            e164 = "+" + digits

        country_name = "International Numbering Plan"
        tz = "UTC"
        cc = ""
        national = digits
        for prefix, cname, ctz in sorted(COUNTRY_CALLING_CODES, key=lambda x: -len(x[0])):
            if digits.startswith(prefix):
                cc = prefix
                country_name = cname
                tz = ctz
                national = digits[len(prefix):]
                break

        region = ""
        line_type = "standard_geographic_or_mobile"
        formatted_national = national
        search_variants = [e164, digits]

        if cc == "1" and len(national) == 10:
            area = national[:3]
            exch = national[3:6]
            sub = national[6:]
            formatted_national = f"({area}) {exch}-{sub}"
            dashed = f"{area}-{exch}-{sub}"
            search_variants.extend([formatted_national, dashed, f"+1-{dashed}"])
            if area in NANPA_AREA_CODES:
                region, tz = NANPA_AREA_CODES[area]
                if "Toll-Free" in region:
                    line_type = "toll_free"
            elif area in ("900", "976"):
                line_type = "premium_rate"
                region = "NANPA Premium Rate"
            else:
                region = f"NANPA Area Code {area}"
        elif len(national) >= 6:
            formatted_national = f"+{cc} {national}" if cc else f"+{digits}"

        return {
            "e164": e164,
            "digits": digits,
            "country_code": f"+{cc}" if cc else "+?",
            "country": country_name,
            "region": region or country_name,
            "timezone": tz,
            "national_format": formatted_national,
            "line_type": line_type,
            "search_variants": list(dict.fromkeys(search_variants))[:4],
        }

    def _search_public_mentions(self, variants: list[str]) -> list[dict[str, str]]:
        mentions: list[dict[str, str]] = []
        query_terms = " OR ".join(f'"{v}"' for v in variants[:2])
        q = urllib.parse.quote(query_terms, safe="")
        url = f"https://api.github.com/search/issues?q={q}&per_page=5"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Find3r-OSINT/0.2",
                "Accept": "application/vnd.github+json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=_default_context()) as resp:
                raw = resp.read(256 * 1024).decode("utf-8", errors="replace")
                data = json.loads(raw)
                if isinstance(data, dict) and isinstance(data.get("items"), list):
                    for item in data["items"][:5]:
                        if isinstance(item, dict) and isinstance(item.get("html_url"), str):
                            title = str(item.get("title") or "Public issue/PR mention").strip()[:120]
                            mentions.append({
                                "source": "github.com",
                                "title": title,
                                "url": item["html_url"],
                            })
        except Exception:
            pass
        return mentions

    def fetch(self, reference: Reference) -> RawResult:
        normalized = resolve_seed(reference.label, "phone")["normalized"]
        plan_info = self._parse_numbering_plan(normalized)
        mentions = self._search_public_mentions(plan_info.get("search_variants") or [normalized])
        payload = {
            "subject": normalized,
            "plan": plan_info,
            "mentions": mentions,
        }
        return RawResult(
            payload=json.dumps(payload, sort_keys=True).encode("utf-8"),
            request_url=reference.url,
            origin_url=reference.origin_url,
            http_status=200,
            content_type="application/json",
            collected_at=datetime.now(timezone.utc),
        )

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        normalized = resolve_seed(request.value, "phone")["normalized"]
        try:
            data = json.loads(raw.payload)
        except Exception as exc:
            raise AdapterError("Invalid phone-osint payload") from exc
        if not isinstance(data, dict):
            raise AdapterError("Unexpected phone-osint payload")

        plan = data.get("plan") or {}
        mentions = data.get("mentions") or []
        facts: list[FactDraft] = []

        def add(attr: str, val: str, value_type: str = "str"):
            if val and str(val).strip():
                facts.append(
                    FactDraft(
                        attribute=attr,
                        value=str(val).strip()[:500],
                        value_type=value_type,
                        entity_kind="phone",
                        entity_name=normalized,
                        identity_key="phone:" + normalized,
                        sensitivity="personal",
                    )
                )

        add("public.phone.e164", plan.get("e164") or normalized)
        add("public.phone.national_format", plan.get("national_format") or normalized)
        add("public.phone.country_code", plan.get("country_code") or "")
        add("public.phone.country", plan.get("country") or "")
        add("public.phone.region", plan.get("region") or "")
        add("public.phone.timezone", plan.get("timezone") or "")
        add("public.phone.line_type", plan.get("line_type") or "standard")
        add("public.phone.public_mention_count", str(len(mentions)), value_type="int")

        for m in mentions[:5]:
            if isinstance(m, dict) and m.get("url"):
                add("public.phone.public_mention", f"{m.get('title', 'Mention')} — {m['url']}")
                add("public.account.url", m["url"])

        return facts
