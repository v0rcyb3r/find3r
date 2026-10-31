"""Enrichment API adapters: Hunter, Apollo, ZoomInfo.

API-derived facts enter as source_type=commercial_api, confidence Medium, and
graded C/3. The guardrail caps single-source commercial_api at Medium (and
corroboration is required for High). No API alone produces a "verified" claim.
"""
from __future__ import annotations

import os
import urllib.parse
from typing import ClassVar

from neesha.collectors.network import http_get_json, http_post_json, redact_url
from neesha.collectors.osint import PassiveCollector
from neesha.evidence.models import (
    AdmiraltyClaimGrade,
    AdmiraltySourceGrade,
    CollectionMode,
    Confidence,
    Evidence,
)
from neesha.scope.engine import ScopeViolation


class EnrichmentAdapter(PassiveCollector):
    agent = "enrichment"
    api_key_env: ClassVar[str] = ""
    description: ClassVar[str] = ""

    def _api_key(self) -> str | None:
        key = os.environ.get(self.api_key_env)
        if not key:
            if self.audit is not None:
                self.audit.log({
                    "action": "api-key-missing",
                    "agent": self.agent,
                    "collector": self.name,
                    "target": self.target,
                    "source": self.source,
                    "scope_id": self.scope.scope.scope_id,
                    "reason": f"env var {self.api_key_env} not set",
                })
            return None
        return key

    def record_api(self, claim: str, source_url: str) -> Evidence:
        return self.record(
            claim=claim,
            source_type="commercial_api",
            source_url=redact_url(source_url),
            confidence=Confidence.MEDIUM,
            source_grade=AdmiraltySourceGrade.C,
            claim_grade=AdmiraltyClaimGrade.THREE,
        )


class HunterAdapter(EnrichmentAdapter):
    name = "hunter"
    source = "hunter"
    api_key_env = "HUNTER_API_KEY"
    description = "Hunter.io email discovery (HUNTER_API_KEY)"

    def run(self) -> list[Evidence]:
        key = self._api_key()
        if not key:
            return []
        domain = self.target
        # The key travels in the request URL because that is the interface
        # Hunter exposes; it must never travel into provenance. These two
        # URLs are deliberately distinct — see redact_url.
        request_url = (
            "https://api.hunter.io/v2/domain-search"
            f"?domain={urllib.parse.quote(domain)}&api_key={key}"
        )
        provenance_url = redact_url(request_url)
        self.authorize(self.source, CollectionMode.PASSIVE)
        try:
            data = http_get_json(request_url)
        except ScopeViolation:
            raise
        except Exception as exc:  # noqa: BLE001
            # Never interpolate the exception without scrubbing: urllib puts
            # the full request URL into HTTPError messages.
            return self._error(f"Hunter query failed: {redact_url(str(exc))}")
        emails = [e.get("value") for e in data.get("data", {}).get("emails", []) if e.get("value")]
        claim = f"Hunter.io reports {len(emails)} email(s) for {domain}: {', '.join(emails[:15]) or 'none'}"
        return [self.record_api(claim, provenance_url)]


class ApolloAdapter(EnrichmentAdapter):
    name = "apollo"
    source = "apollo"
    api_key_env = "APOLLO_API_KEY"
    description = "Apollo.io people search (APOLLO_API_KEY)"

    def run(self) -> list[Evidence]:
        key = self._api_key()
        if not key:
            return []
        domain = self.target
        url = "https://api.apollo.io/v1/mixed_people/search"
        self.authorize(self.source, CollectionMode.PASSIVE)
        try:
            data = http_post_json(
                url,
                {"q_organization_domains": domain, "page": 1, "per_page": 10},
                headers={"X-Api-Key": key},
            )
        except ScopeViolation:
            raise
        except Exception as exc:  # noqa: BLE001
            return self._error(f"Apollo query failed: {exc}")
        people = data.get("people", []) if isinstance(data, dict) else []
        names = [f"{p.get('first_name', '')} {p.get('last_name', '')}".strip() for p in people]
        claim = f"Apollo reports {len(people)} people at {domain}: {', '.join(names[:15]) or 'none'}"
        return [self.record_api(claim, url)]


class ZoomInfoAdapter(EnrichmentAdapter):
    name = "zoominfo"
    source = "zoominfo"
    api_key_env = "ZOOMINFO_API_KEY"
    description = "ZoomInfo (enterprise OAuth; adapter reserved)"

    def run(self) -> list[Evidence]:
        # ZoomInfo requires enterprise OAuth and a paired search endpoint; a
        # plain API key is not a supported path. Skip honestly rather than
        # fabricate a request that cannot work.
        return self._error("ZoomInfo requires enterprise OAuth; direct-call adapter not implemented")


class EnrichmentRouter:
    """Multi-provider routing: Hunter first for email, ZoomInfo for enterprise
    people where economics justify, Apollo as fallback."""

    @staticmethod
    def route(task: str, enterprise: bool = False) -> list[str]:
        if task == "people" and enterprise:
            return ["zoominfo", "apollo", "hunter"]
        if task == "email":
            return ["hunter", "apollo", "zoominfo"]
        return ["apollo", "hunter", "zoominfo"]
