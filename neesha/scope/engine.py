"""Scope engine: blocks any collection the scope file does not authorize.

Every collector calls ``engine.authorize(source, mode)`` before touching a
source. Out-of-scope, denied, expired, or unauthorized-active actions are
refused with a reason.
"""
from __future__ import annotations

from dataclasses import dataclass

from neesha.evidence.models import CollectionMode
from neesha.scope.models import Scope


class ScopeViolation(Exception):
    """Raised when code attempts to collect outside its scope."""


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str = ""
    scope_id: str = ""


class ScopeEngine:
    def __init__(self, scope: Scope):
        self.scope = scope

    def authorize(self, source: str, mode: CollectionMode) -> ScopeDecision:
        scope = self.scope
        if scope.is_expired():
            return ScopeDecision(
                False,
                f"scope {scope.scope_id} expired at {scope.expires_at.isoformat()}",
                scope.scope_id,
            )
        if scope.denied_sources and source in scope.denied_sources:
            return ScopeDecision(False, f"source {source!r} is denied", scope.scope_id)
        if scope.allowed_sources and source not in scope.allowed_sources:
            return ScopeDecision(
                False, f"source {source!r} is not in the allowed list", scope.scope_id
            )
        if mode == CollectionMode.ACTIVE and not scope.active_authorized:
            return ScopeDecision(
                False,
                "active collection requires explicit authorization (scope.active_authorized)",
                scope.scope_id,
            )
        if mode not in scope.allowed_modes:
            return ScopeDecision(
                False, f"mode {mode.value!r} is not allowed for this scope", scope.scope_id
            )
        return ScopeDecision(True, scope_id=scope.scope_id)
