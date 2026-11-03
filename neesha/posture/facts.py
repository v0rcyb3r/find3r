"""Parsed posture facts, independent of collection and grading.

These are the typed results the grader consumes. The raw records that back
them travel separately in the Brief's checks, so a grade is never shown
without its underlying record.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SPFResult(BaseModel):
    present: bool = False
    record: Optional[str] = None
    qualifier: Optional[str] = None  # -all | ~all | ?all | +all
    unstable: bool = False


class DMARCResult(BaseModel):
    present: bool = False
    record: Optional[str] = None
    policy: Optional[str] = None  # none | quarantine | reject
    subdomain_policy: Optional[str] = None
    pct: Optional[int] = None
    rua: Optional[str] = None
    ruf: Optional[str] = None
    unstable: bool = False


class DKIMResult(BaseModel):
    selectors_found: list[str] = Field(default_factory=list)
    selectors_checked: list[str] = Field(default_factory=list)
    wildcard: bool = False
    note: str = "selector coverage limited"


class MTASTSResult(BaseModel):
    present: bool = False
    record: Optional[str] = None


class TLSRPTResult(BaseModel):
    present: bool = False
    record: Optional[str] = None


class TLSResult(BaseModel):
    connected: bool = False
    issuer: Optional[str] = None
    not_after: Optional[datetime] = None
    san: list[str] = Field(default_factory=list)
    days_remaining: Optional[int] = None
    error: Optional[str] = None


class HTTPResult(BaseModel):
    fetched: bool = False
    https_available: bool = False
    final_url: Optional[str] = None
    status: Optional[int] = None
    hsts: Optional[str] = None
    csp: bool = False
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    referrer_policy: bool = False
    permissions_policy: bool = False
    error: Optional[str] = None


class DNSSECResult(BaseModel):
    status: str = "unknown"  # validated | signed-not-validated | unsigned | unknown
    ad: Optional[bool] = None
    keys_present: bool = False


class DNSResult(BaseModel):
    a: list[str] = Field(default_factory=list)
    aaaa: list[str] = Field(default_factory=list)
    mx: list[str] = Field(default_factory=list)
    ns: list[str] = Field(default_factory=list)
    soa: list[str] = Field(default_factory=list)
    caa: list[str] = Field(default_factory=list)


class Grade(BaseModel):
    letter: str
    score: int
    rationale: str


class Trigger(BaseModel):
    signal: str
    why_now: str
    offering: str

