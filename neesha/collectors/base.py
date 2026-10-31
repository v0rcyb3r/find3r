"""Collector base class: the shared contract for all Neesha collectors.

Every collector declares its name and agent, authorizes each source through
the scope engine, and writes Evidence with full provenance. Active collectors
are gated by the scope engine's ``active_authorized`` flag.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import timedelta
from typing import ClassVar, Optional

from neesha.audit import AuditLog
from neesha.collectors.network import redact_url
from neesha.evidence.models import (
    AdmiraltyClaimGrade,
    AdmiraltySourceGrade,
    CollectionMode,
    Confidence,
    Evidence,
    utcnow,
)
from neesha.evidence.store import EvidenceStore
from neesha.scope.engine import ScopeEngine, ScopeViolation


class Collector(ABC):
    name: ClassVar[str] = "collector"
    agent: ClassVar[str] = "collector"
    # Cost tier, per the spec: A free/always-on, B metered, C manual and
    # authority-gated, D contract-gated and disabled by default.
    tier: ClassVar[str] = "A"
    # The mode this collector actually operates in. record() stamps evidence
    # with this rather than hardcoding "passive", so an active collector
    # cannot file its results as passive. AUDIT.md B5.
    collection_mode: ClassVar[CollectionMode] = CollectionMode.PASSIVE

    def __init__(
        self, scope: ScopeEngine, store: EvidenceStore, target: str, audit: Optional[AuditLog] = None
    ):
        self.scope = scope
        self.store = store
        self.target = target
        self.audit = audit

    def authorize(
        self, source: str, mode: CollectionMode = CollectionMode.PASSIVE
    ) -> None:
        decision = self.scope.authorize(source, mode)
        if not decision.allowed:
            if self.audit is not None:
                self.audit.log({
                    "action": "collection-denied",
                    "agent": self.agent,
                    "collector": self.name,
                    "target": self.target,
                    "source": source,
                    "mode": mode.value,
                    "scope_id": self.scope.scope.scope_id,
                    "reason": decision.reason,
                })
            raise ScopeViolation(f"{self.name}: {decision.reason}")

    def record(
        self,
        *,
        claim: str,
        source_type: str,
        source_url: Optional[str] = None,
        entity_id: Optional[str] = None,
        confidence: Confidence = Confidence.HIGH,
        source_grade: AdmiraltySourceGrade = AdmiraltySourceGrade.B,
        claim_grade: AdmiraltyClaimGrade = AdmiraltyClaimGrade.TWO,
        is_inference: bool = False,
        mode: Optional[CollectionMode] = None,
    ) -> Evidence:
        """Write one Evidence record and return it (with its assigned id)."""
        evidence = Evidence(
            target_id=self.target,
            entity_id=entity_id,
            claim=claim,
            # Redact here, not at the call site: this is the one path every
            # collector takes, so a careless adapter cannot leak a key into
            # the ledger or an exported report.
            source_url=redact_url(source_url) if source_url else None,
            source_type=source_type,
            collection_mode=mode or self.collection_mode,
            collector=self.name,
            agent=self.agent,
            scope_id=self.scope.scope.scope_id,
            confidence=confidence,
            admiralty_source_grade=source_grade,
            admiralty_claim_grade=claim_grade,
            is_inference=is_inference,
            retention_expires_at=utcnow() + timedelta(days=self.scope.scope.retention_days),
        )
        self.store.insert(evidence)
        if self.audit is not None:
            self.audit.log({
                "action": "evidence",
                "agent": evidence.agent,
                "collector": evidence.collector,
                "target": evidence.target_id,
                "source": evidence.source_type,
                "mode": evidence.collection_mode.value,
                "scope_id": evidence.scope_id,
                "evidence_id": evidence.evidence_id,
            })
        return evidence

    @abstractmethod
    def run(self) -> list[Evidence]:
        """Execute collection and return the Evidence records written."""
