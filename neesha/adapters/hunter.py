"""Hunter.io — business email discovery. Tier B, metered.

Two things about this adapter carry more weight than the parsing:

**The key never enters provenance.** The request URL and the recorded URL are
deliberately different objects. Hunter takes its key as a query parameter, so
the credentialed URL exists, but what reaches ``source_record.request_url``
and therefore any exported report is the redacted form. This is the leak
AUDIT.md P1 documented, closed at the point where it originated.

**Everything here is business-contact data.** Hunter returns a person's work
email, department and seniority — facts about a role at a company, which is
what the People & Org tab is for. The adapter never emits a personal address,
and it attaches every person to the company rather than standing them up as
an independent subject. Under Hunter's terms we are an independent GDPR
controller for what we retrieve, which is why retention here is short and the
purge job is a compliance control.
"""
from __future__ import annotations

import json
import os
import urllib.parse
from typing import ClassVar, Optional

from neesha.adapters.base import (
    AdapterError,
    BaseAdapter,
    Cost,
    FactDraft,
    RawResult,
    Reference,
    Request,
)
from neesha.collectors.network import http_get, redact_url

API_KEY_ENV = "HUNTER_API_KEY"

# Cost per domain-search request. Hunter's paid plans bill per request; the
# free tier allows a small monthly allowance. This figure is the ledger's
# estimate and is settled with the actual afterwards — confirm the current
# rate against your plan rather than trusting this constant.
ESTIMATED_USD_PER_SEARCH = 0.01

# Short on purpose: personal data we control, so we keep it only as long as a
# briefing cycle needs it.
RETENTION_DAYS = 30


class HunterAdapter(BaseAdapter):
    name: ClassVar[str] = "hunter"
    tier: ClassVar[str] = "B"
    collection_mode: ClassVar[str] = "third_party_passive"
    description: ClassVar[str] = "Hunter.io business email discovery (metered)"
    source_type: ClassVar[str] = "commercial_api"
    produces: ClassVar[frozenset[str]] = frozenset(
        {"person.business_email", "person.role", "person.seniority", "email.pattern"}
    )
    accepts: ClassVar[frozenset[str]] = frozenset({"company", "domain"})
    retention_days: ClassVar[int] = RETENTION_DAYS

    max_people: ClassVar[int] = 100

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key

    # ---- cost ------------------------------------------------------------

    def estimate_cost(self, request: Request) -> Cost:
        return Cost(usd=ESTIMATED_USD_PER_SEARCH, basis="per_call")

    def api_key(self) -> str:
        key = self._api_key or os.environ.get(API_KEY_ENV)
        if not key:
            raise AdapterError(
                f"{API_KEY_ENV} is not set; Hunter cannot run without it"
            )
        return key

    # ---- collection ------------------------------------------------------

    def search(self, request: Request) -> list[Reference]:
        domain = request.value.strip().lower().rstrip(".")
        limit = int(request.params.get("limit", self.max_people))
        # The credentialed URL and the URL we will record are separate on
        # purpose. Only the redacted one is allowed to persist.
        request_url = (
            "https://api.hunter.io/v2/domain-search"
            f"?domain={urllib.parse.quote(domain)}"
            f"&limit={limit}&api_key={self.api_key()}"
        )
        return [
            Reference(
                url=request_url,
                origin_url=f"https://hunter.io/domain/{domain}",
                label=domain,
            )
        ]

    def fetch(self, reference: Reference) -> RawResult:
        try:
            body = http_get(reference.url, timeout=30)
        except Exception as exc:  # noqa: BLE001
            # urllib puts the full request URL into HTTPError messages, so
            # the exception text has to be scrubbed before it reaches a log.
            raise AdapterError(
                f"Hunter fetch failed: {redact_url(str(exc))}"
            ) from None
        return RawResult(
            payload=body.encode("utf-8", errors="replace"),
            # Redacted here, once, so no downstream caller has to remember.
            request_url=redact_url(reference.url),
            origin_url=reference.origin_url,
            http_status=200,
            content_type="application/json",
        )

    def parse(self, raw: RawResult, request: Request) -> list[FactDraft]:
        domain = request.value.strip().lower().rstrip(".")
        try:
            body = json.loads(raw.payload.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise AdapterError(f"Hunter returned unparseable JSON: {exc}") from exc

        data = body.get("data") if isinstance(body, dict) else None
        if not isinstance(data, dict):
            raise AdapterError("Hunter response had no data object")

        drafts: list[FactDraft] = []

        pattern = data.get("pattern")
        if pattern:
            # An org-level fact, not a person-level one: the shape of the
            # address, which is often all an analyst needs.
            drafts.append(
                FactDraft(
                    attribute="email.pattern",
                    value=str(pattern),
                    entity_kind="domain",
                    entity_name=domain,
                )
            )

        for record in (data.get("emails") or [])[: self.max_people]:
            if not isinstance(record, dict):
                continue
            address = (record.get("value") or "").strip().lower()
            if not address or "@" not in address:
                continue

            first = (record.get("first_name") or "").strip()
            last = (record.get("last_name") or "").strip()
            person = " ".join(p for p in (first, last) if p) or address

            drafts.append(
                FactDraft(
                    attribute="person.business_email",
                    value=address,
                    entity_kind="person",
                    entity_name=person,
                    value_type="email",
                )
            )
            if record.get("position"):
                drafts.append(
                    FactDraft(
                        attribute="person.role",
                        value=str(record["position"]).strip(),
                        entity_kind="person",
                        entity_name=person,
                    )
                )
            if record.get("seniority"):
                drafts.append(
                    FactDraft(
                        attribute="person.seniority",
                        value=str(record["seniority"]).strip(),
                        entity_kind="person",
                        entity_name=person,
                    )
                )

        return drafts
