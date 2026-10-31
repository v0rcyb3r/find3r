"""Provenance-first data models: Evidence, Entity, Signal.

These are the contract from spec section 3. Every factual claim in Neesha
is an Evidence record carrying source, collection mode, confidence, and an
Admiralty source/claim grade. Do not loosen these fields.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CollectionMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class AdmiraltySourceGrade(str, Enum):
    """Reliability of the source (A = most reliable .. F = cannot be judged)."""
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


class AdmiraltyClaimGrade(str, Enum):
    """Credibility of the claim (1 = confirmed .. 6 = cannot be judged)."""
    ONE = "1"
    TWO = "2"
    THREE = "3"
    FOUR = "4"
    FIVE = "5"
    SIX = "6"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Evidence(BaseModel):
    """A single factual claim with full provenance."""

    evidence_id: str = Field(default_factory=lambda: uuid4().hex)
    target_id: str
    entity_id: Optional[str] = None
    claim: str
    source_url: Optional[str] = None
    origin_url: Optional[str] = None  # canonical origin for circular-reporting detection
    source_type: str  # dns | tls | http | commercial_api | social | vendor_graph | osint
    collected_at: datetime = Field(default_factory=utcnow)
    collection_mode: CollectionMode
    collector: str
    agent: str
    scope_id: str
    confidence: Confidence = Confidence.UNKNOWN
    admiralty_source_grade: AdmiraltySourceGrade = AdmiraltySourceGrade.F
    admiralty_claim_grade: AdmiraltyClaimGrade = AdmiraltyClaimGrade.SIX
    retention_expires_at: datetime = Field(default_factory=utcnow)
    # Fact vs. inference: an inference must be labeled, never presented as fact.
    is_inference: bool = False
    # Guardrail flags (e.g. "single-source", "circular-reporting"). Set by Phase 2.
    flags: list[str] = Field(default_factory=list)


class Entity(BaseModel):
    entity_id: str = Field(default_factory=lambda: uuid4().hex)
    type: str  # person | company | asset | email | phone | ip | domain
    canonical_name: str
    aliases: list[str] = Field(default_factory=list)
    identifiers: dict[str, Any] = Field(default_factory=dict)
    confidence: Confidence = Confidence.UNKNOWN
    merge_history: list[str] = Field(default_factory=list)
    resolved_by: Optional[str] = None
    evidence_ids: list[str] = Field(default_factory=list)


class Signal(BaseModel):
    signal_id: str = Field(default_factory=lambda: uuid4().hex)
    entity_id: str
    # posture_gap | leadership_change | vendor_displacement | public_pain |
    # infrastructure_change | funding | hiring | legal_event | news
    type: str
    description: str
    why_now: str
    source_evidence_ids: list[str] = Field(default_factory=list)
    score: float = 0.0
    confidence: Confidence = Confidence.UNKNOWN
    suggested_action: Optional[str] = None


class Relationship(BaseModel):
    """A directed edge between two entities, backed by evidence."""
    relationship_id: str = Field(default_factory=lambda: uuid4().hex)
    source_entity_id: str
    target_entity_id: str
    # subdomain_of | resolves_to | employee_of | owner_of | mentions | same_as
    relationship_type: str
    confidence: Confidence = Confidence.UNKNOWN
    evidence_ids: list[str] = Field(default_factory=list)
