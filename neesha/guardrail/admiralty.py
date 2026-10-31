"""Admiralty-style source/claim grading.

Two axes, graded independently:

- Source reliability (A-F): how trustworthy the source is.
  A = fully reliable (official record), B = usually reliable (direct
  observation), C = fairly reliable (third-party data), D = not usually
  reliable (single social post), E = unreliable, F = cannot be judged.
- Claim credibility (1-6): how likely the claim is true.
  1 = confirmed by independent sources, 2 = probably true, 3 = possibly true,
  4 = doubtfully true, 5 = improbable, 6 = cannot be judged.

Grades are computed from source_type (the collector never self-grades above
what its source warrants).
"""
from __future__ import annotations

from typing import Optional

from neesha.evidence.models import AdmiraltySourceGrade

_A = AdmiraltySourceGrade.A
_B = AdmiraltySourceGrade.B
_C = AdmiraltySourceGrade.C
_D = AdmiraltySourceGrade.D
_F = AdmiraltySourceGrade.F

SOURCE_GRADE_TABLE: dict[str, AdmiraltySourceGrade] = {
    # authoritative records
    "sec_filing": _A,
    "registrar": _A,
    "official": _A,
    # direct, verifiable observations
    "dns": _B,
    "tls": _B,
    "http": _B,
    "dnssec": _B,
    "whois": _B,
    # third-party / aggregated data
    "press": _C,
    "osint": _C,
    "osint_aggregate": _C,
    "commercial_api": _C,
    # weakly reliable
    "social": _D,
    "blog": _D,
}

# Base claim credibility (1-6) by source type, before corroboration.
CLAIM_BASE_TABLE: dict[str, int] = {
    "sec_filing": 2,
    "registrar": 2,
    "official": 2,
    "dns": 2,
    "tls": 2,
    "http": 2,
    "dnssec": 2,
    "whois": 2,
    "press": 3,
    "osint": 3,
    "osint_aggregate": 3,
    "commercial_api": 3,
    "social": 4,
    "blog": 4,
}


def grade_source(source_type: str, source_url: Optional[str] = None) -> AdmiraltySourceGrade:
    return SOURCE_GRADE_TABLE.get(source_type, _F)


def grade_claim(source_type: str, is_inference: bool = False, corroborated: bool = False) -> int:
    """Return a claim credibility grade (1-6).

    Corroboration by an independent source improves the grade one notch.
    An inference can never be graded "confirmed"/"probably true" (1-2).
    """
    base = CLAIM_BASE_TABLE.get(source_type, 6)
    if corroborated:
        base = max(1, base - 1)
    if is_inference:
        base = max(base, 3)
    return base
