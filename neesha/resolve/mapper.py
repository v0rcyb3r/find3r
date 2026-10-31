"""Network mapper: build relationships between resolved entities.

Phase 4 relationships are infrastructure edges: ``subdomain_of`` (asset ->
domain) and ``resolves_to`` (domain/asset -> ip), derived from DNS evidence.
Employment/ownership/mentions edges arrive with later phases.
"""
from __future__ import annotations

import re

from neesha.evidence.models import Confidence, Entity, Evidence, Relationship
from neesha.resolve.normalize import canonicalize_domain, extract_ips, is_subdomain

_A_CLAIM_RE = re.compile(r"^(?:A|AAAA) records for (?P<host>[^:]+):")


class NetworkMapper:
    def map(self, entities: list[Entity], evidence_list: list[Evidence], seed: str) -> list[Relationship]:
        by_canon = {e.canonical_name: e.entity_id for e in entities}
        seed = canonicalize_domain(seed)
        seed_id = by_canon.get(seed)
        relationships: list[Relationship] = []

        for entity in entities:
            if entity.type == "asset" and seed_id and is_subdomain(entity.canonical_name, seed):
                relationships.append(Relationship(
                    source_entity_id=entity.entity_id,
                    target_entity_id=seed_id,
                    relationship_type="subdomain_of",
                    confidence=Confidence.HIGH,
                ))

        for ev in evidence_list:
            match = _A_CLAIM_RE.match(ev.claim.strip())
            if not match:
                continue
            host = canonicalize_domain(match.group("host"))
            if host not in by_canon:
                continue
            for ip in extract_ips(ev.claim):
                if ip in by_canon:
                    relationships.append(Relationship(
                        source_entity_id=by_canon[host],
                        target_entity_id=by_canon[ip],
                        relationship_type="resolves_to",
                        confidence=Confidence.HIGH,
                        evidence_ids=[ev.evidence_id],
                    ))

        return relationships


def to_mermaid(entities: list[Entity], relationships: list[Relationship]) -> str:
    lines = ["graph TD"]
    for entity in entities:
        label = f"{entity.canonical_name} ({entity.type})"
        node_id = entity.entity_id[:8]
        lines.append(f'  {node_id}["{label}"]')
    for rel in relationships:
        src = rel.source_entity_id[:8]
        dst = rel.target_entity_id[:8]
        lines.append(f"  {src} -->|{rel.relationship_type}| {dst}")
    return "\n".join(lines)
