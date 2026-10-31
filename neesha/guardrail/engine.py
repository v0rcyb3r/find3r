"""The accuracy guardrail: a hard gate over evidence.

Applied to every Evidence record before a report is emitted:

- unsourced claims are dropped;
- single-source claims are flagged;
- circular reporting (multiple records tracing to one origin) collapses to a
  single source and is flagged;
- confidence ceilings are enforced: a single secondary source (commercial API,
  press, OSINT aggregate) is capped at Medium;
- weak single-source claims are downgraded (lenient) or dropped (strict);
- inferences are flagged and their claim grade floored at 3 (never "fact").

The guardrail is authoritative over grades: it recomputes source/claim grades
from source_type rather than trusting the collector's self-assigned grade.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

from pydantic import BaseModel, Field

from neesha.evidence.models import (
    AdmiraltyClaimGrade,
    AdmiraltySourceGrade,
    Confidence,
    Evidence,
)
from neesha.guardrail.admiralty import grade_claim, grade_source

_CONF_RANK = {
    Confidence.UNKNOWN: 0,
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}
_DOWNGRADE = {
    Confidence.HIGH: Confidence.MEDIUM,
    Confidence.MEDIUM: Confidence.LOW,
    Confidence.LOW: Confidence.UNKNOWN,
    Confidence.UNKNOWN: Confidence.UNKNOWN,
}
_WEAK_SOURCE = {AdmiraltySourceGrade.D, AdmiraltySourceGrade.E, AdmiraltySourceGrade.F}
_WEAK_CLAIM = {4, 5, 6}

# A single uncorroborated secondary source may not exceed this confidence.
# Corroboration (2+ independent origins) lifts the cap. Direct observations
# (dns/tls/http/whois) and authoritative records (sec_filing/registrar/official)
# have no cap. Weak sources (social/blog) are handled by the weak-single-source
# rule instead.
CONFIDENCE_CEILINGS: dict[str, Confidence] = {
    "commercial_api": Confidence.MEDIUM,
    "press": Confidence.MEDIUM,
    "osint": Confidence.MEDIUM,
    "osint_aggregate": Confidence.MEDIUM,
}


class ClaimVerdict(BaseModel):
    evidence_id: str
    claim: str
    source_grade: AdmiraltySourceGrade
    claim_grade: AdmiraltyClaimGrade
    confidence: Confidence
    is_inference: bool
    action: str  # keep | downgraded | dropped
    downgraded_from: Optional[Confidence] = None
    flags: list[str] = Field(default_factory=list)
    reason: str = "ok"

    @property
    def grade(self) -> str:
        return f"{self.source_grade.value}{self.claim_grade.value}"


class GuardrailReport(BaseModel):
    total: int
    kept: int
    downgraded: int
    dropped: int
    strict: bool
    verdicts: list[ClaimVerdict] = Field(default_factory=list)

    def survived(self) -> list[ClaimVerdict]:
        return [v for v in self.verdicts if v.action != "dropped"]

    def to_markdown(self) -> str:
        lines = [
            "# Accuracy Guardrail Report",
            "",
            f"Total: {self.total} | Kept: {self.kept} | Downgraded: {self.downgraded} "
            f"| Dropped: {self.dropped} | Strict: {self.strict}",
            "",
        ]
        for v in self.verdicts:
            lines.append(f"## {v.evidence_id} — `{v.action}`")
            lines.append(f"[CLAIM] {v.claim}")
            lines.append(f"[GRADE] {v.grade}")
            lines.append(f"[FLAGS] {', '.join(v.flags) or 'none'}")
            lines.append(f"[CONFIDENCE] {v.confidence.value}")
            if v.downgraded_from:
                lines.append(f"[DOWNGRADED FROM] {v.downgraded_from.value}")
            lines.append("")
        return "\n".join(lines)


def _claim_key(claim: str) -> str:
    return re.sub(r"\W+", " ", claim.lower()).strip()


def _origin(e: Evidence) -> str:
    return e.origin_url or e.source_url or e.source_type or "unsourced"


class Guardrail:
    @staticmethod
    def apply(evidence_list: list[Evidence], strict: bool = False) -> GuardrailReport:
        groups: dict[str, list[Evidence]] = defaultdict(list)
        for e in evidence_list:
            groups[_claim_key(e.claim)].append(e)

        verdicts: list[ClaimVerdict] = []
        for group in groups.values():
            origins = {_origin(e) for e in group}
            distinct = len(origins)
            corroborated = distinct >= 2
            single_source = distinct == 1
            circular = len(group) > 1 and distinct == 1
            for e in group:
                verdicts.append(Guardrail._judge(e, corroborated, single_source, circular, strict))

        verdicts.sort(key=lambda v: v.evidence_id)
        kept = sum(1 for v in verdicts if v.action == "keep")
        downgraded = sum(1 for v in verdicts if v.action == "downgraded")
        dropped = sum(1 for v in verdicts if v.action == "dropped")
        return GuardrailReport(
            total=len(verdicts),
            kept=kept,
            downgraded=downgraded,
            dropped=dropped,
            strict=strict,
            verdicts=verdicts,
        )

    @staticmethod
    def _judge(
        e: Evidence, corroborated: bool, single_source: bool, circular: bool, strict: bool
    ) -> ClaimVerdict:
        flags = list(e.flags)
        original = e.confidence
        confidence = e.confidence
        action = "keep"
        reasons: list[str] = []

        if not e.source_type:
            flags.append("unsourced")
            return ClaimVerdict(
                evidence_id=e.evidence_id,
                claim=e.claim,
                source_grade=AdmiraltySourceGrade.F,
                claim_grade=AdmiraltyClaimGrade.SIX,
                confidence=confidence,
                is_inference=e.is_inference,
                action="dropped",
                flags=flags,
                reason="unsourced",
            )

        if single_source:
            flags.append("single-source")
        if circular:
            flags.append("circular-reporting")
        if e.is_inference:
            flags.append("inference")

        source_grade = grade_source(e.source_type, e.source_url)
        claim_grade = grade_claim(e.source_type, e.is_inference, corroborated)

        ceiling = CONFIDENCE_CEILINGS.get(e.source_type)
        if ceiling and not corroborated and _CONF_RANK[confidence] > _CONF_RANK[ceiling]:
            confidence = ceiling
            flags.append("confidence-capped")
            reasons.append(f"single-source {e.source_type} capped at {ceiling.value}")

        weak = source_grade in _WEAK_SOURCE or claim_grade in _WEAK_CLAIM
        if weak and single_source:
            if strict:
                action = "dropped"
                flags.append("dropped-weak-single-source")
                reasons.append("weak single source")
            else:
                confidence = _DOWNGRADE[confidence]
                flags.append("downgraded-weak-single-source")
                reasons.append("weak single source")

        if action != "dropped" and confidence != original:
            action = "downgraded"

        return ClaimVerdict(
            evidence_id=e.evidence_id,
            claim=e.claim,
            source_grade=source_grade,
            claim_grade=AdmiraltyClaimGrade(str(claim_grade)),
            confidence=confidence,
            is_inference=e.is_inference,
            action=action,
            downgraded_from=original if action == "downgraded" else None,
            flags=flags,
            reason="; ".join(reasons) or "ok",
        )
