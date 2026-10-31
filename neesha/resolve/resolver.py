"""Entity resolver: extract, canonicalize, group, and merge entities.

Never silently merges: candidate merges whose similarity falls below the high
threshold are flagged for review, not forced. Entity confidence is derived
from the number of distinct source types that corroborate it.
"""
from __future__ import annotations

from difflib import SequenceMatcher
from typing import Optional

from pydantic import BaseModel, Field

from neesha.evidence.models import Confidence, Entity, Evidence
from neesha.resolve.normalize import (
    canonicalize_domain,
    canonicalize_email,
    canonicalize_ip,
    extract_domains,
    extract_emails,
    extract_ips,
)


class FlaggedMerge(BaseModel):
    entity_a_id: str
    entity_b_id: str
    similarity: float
    reason: str


class ResolutionResult(BaseModel):
    seed: str
    entities: list[Entity] = Field(default_factory=list)
    flagged_merges: list[FlaggedMerge] = Field(default_factory=list)


class EntityResolver:
    # String-similarity merging is only meaningful for names (people/orgs) and
    # domains. IPs, emails, phones, and hostnames are exact-match only: two
    # IPv6 addresses sharing a /64 prefix are different entities, not aliases.
    MERGEABLE_TYPES = {"person", "company", "org", "domain"}

    def __init__(self, merge_high: float = 0.9, merge_low: float = 0.5):
        self.merge_high = merge_high
        self.merge_low = merge_low

    # ---- resolution --------------------------------------------------------

    def resolve(self, seed: str, evidence_list: list[Evidence]) -> ResolutionResult:
        domain = canonicalize_domain(seed)
        acc: dict[str, dict] = {}
        # The seed is itself a fact; record it even with no supporting evidence.
        self._accumulate(acc, "domain", domain, None, None, None)

        for ev in evidence_list:
            for host in extract_domains(ev.claim):
                canon = canonicalize_domain(host)
                if canon == domain:
                    etype = "domain"
                elif canon.endswith("." + domain):
                    etype = "asset"
                else:
                    continue  # unrelated mention, out of scope for the map
                self._accumulate(acc, etype, canon, host, ev.evidence_id, ev.source_type)
            for ip in extract_ips(ev.claim):
                self._accumulate(acc, "ip", canonicalize_ip(ip), ip, ev.evidence_id, ev.source_type)
            for email in extract_emails(ev.claim):
                self._accumulate(acc, "email", canonicalize_email(email), email, ev.evidence_id, ev.source_type)

        entities = [self._to_entity(canon, data) for canon, data in acc.items()]
        merged, flagged = self.merge_candidates(entities)
        return ResolutionResult(seed=domain, entities=merged, flagged_merges=flagged)

    @staticmethod
    def _accumulate(
        acc: dict[str, dict],
        etype: str,
        canon: str,
        raw: Optional[str],
        evidence_id: Optional[str],
        source_type: Optional[str],
    ) -> None:
        entry = acc.setdefault(canon, {
            "type": etype,
            "aliases": set(),
            "evidence_ids": set(),
            "source_types": set(),
        })
        if raw and raw != canon:
            entry["aliases"].add(raw)
        if evidence_id:
            entry["evidence_ids"].add(evidence_id)
        if source_type:
            entry["source_types"].add(source_type)

    @staticmethod
    def _to_entity(canon: str, data: dict) -> Entity:
        source_types = data["source_types"]
        if len(source_types) >= 2:
            confidence = Confidence.HIGH
        elif len(source_types) == 1:
            confidence = Confidence.MEDIUM
        else:
            confidence = Confidence.LOW
        return Entity(
            type=data["type"],
            canonical_name=canon,
            aliases=sorted(data["aliases"]),
            confidence=confidence,
            resolved_by="entity-resolver",
            evidence_ids=sorted(data["evidence_ids"]),
        )

    # ---- merge with confidence --------------------------------------------

    def merge_candidates(self, entities: list[Entity]) -> tuple[list[Entity], list[FlaggedMerge]]:
        merged = list(entities)
        flagged: list[FlaggedMerge] = []
        i = 0
        while i < len(merged):
            j = i + 1
            while j < len(merged):
                a, b = merged[i], merged[j]
                if a.type == b.type and a.type in self.MERGEABLE_TYPES:
                    similarity = SequenceMatcher(None, a.canonical_name, b.canonical_name).ratio()
                    if similarity >= self.merge_high:
                        merged[i] = self._merge(a, b)
                        merged.pop(j)
                        continue
                    if similarity >= self.merge_low:
                        flagged.append(FlaggedMerge(
                            entity_a_id=a.entity_id,
                            entity_b_id=b.entity_id,
                            similarity=round(similarity, 3),
                            reason="similar names below merge threshold",
                        ))
                j += 1
            i += 1
        return merged, flagged

    @staticmethod
    def _merge(a: Entity, b: Entity) -> Entity:
        aliases = sorted(set(a.aliases) | {b.canonical_name} | set(b.aliases))
        evidence_ids = sorted(set(a.evidence_ids) | set(b.evidence_ids))
        confidence = a.confidence if a.confidence.value != "unknown" else b.confidence
        return a.model_copy(update={
            "aliases": aliases,
            "evidence_ids": evidence_ids,
            "confidence": confidence,
            "merge_history": a.merge_history + [f"merged {b.entity_id} ({b.canonical_name})"],
            "resolved_by": "entity-resolver",
        })
