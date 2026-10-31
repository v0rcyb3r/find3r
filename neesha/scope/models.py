"""Scope model: the authorization contract for a run.

Passive-by-default is enforced here: ``allowed_modes`` defaults to passive
only, and active collection requires ``active_authorized=True`` set by an
explicit authorization step.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from neesha.evidence.models import CollectionMode


def _default_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=30)


class Scope(BaseModel):
    scope_id: str = Field(default_factory=lambda: uuid4().hex)
    target: str
    target_type: str  # domain | org | person | email | phone | ip
    purpose: str
    observer: str  # strongest observer, e.g. "ISP", "VPS provider", "target"
    allowed_sources: list[str] = Field(default_factory=list)
    denied_sources: list[str] = Field(default_factory=list)
    allowed_modes: list[CollectionMode] = Field(
        default_factory=lambda: [CollectionMode.PASSIVE]
    )
    denied_techniques: list[str] = Field(default_factory=list)
    active_authorized: bool = False
    retention_days: int = 30
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(default_factory=_default_expiry)
    authorized_by: Optional[str] = None

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return now >= self.expires_at

    @model_validator(mode="after")
    def _sync_active_mode(self) -> "Scope":
        # Granting active authorization must also permit the active mode.
        if self.active_authorized and CollectionMode.ACTIVE not in self.allowed_modes:
            self.allowed_modes = [*self.allowed_modes, CollectionMode.ACTIVE]
        return self
