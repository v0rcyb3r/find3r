"""The policy gate: outbound call authorization, run caps, and budget reservation.

Every tool call passes through ``PolicyGate.authorize`` before execution. It
checks, in this order:

1. the engagement is in force;
2. the target is one the engagement authorizes;
3. the adapter's tier is enabled (Tier D stub adapters are disabled);
4. active collection techniques (``active_scan``) are permitted when ``collection_mode == 'active'``;
5. the run's own caps — steps, wall time, spend — are not spent;
6. whether this tier is configured in ``approval_tiers``;
7. the budget, by taking a reservation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Literal, Optional

import sqlalchemy as sa

from neesha.db import schema
from neesha.ledger.ledger import (
    BudgetExceeded,
    Ledger,
    NoBudgetConfigured,
    Reservation,
    period_of,
)

Outcome = Literal["allowed", "denied", "paused"]

# By default, no tiers pause for manual approval unless explicitly configured.
DEFAULT_APPROVAL_TIERS: frozenset[str] = frozenset()

ACTIVE_TECHNIQUE = "active_scan"


@dataclass(frozen=True)
class AdapterSpec:
    """What the gate needs to know about an adapter."""

    name: str
    tier: str
    collection_mode: str = "third_party_passive"
    requires_techniques: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class EngagementView:
    id: str
    authority_basis: str
    permitted_techniques: frozenset[str] = field(default_factory=frozenset)
    authorized_domains: tuple[str, ...] = ()
    starts_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    authorized_emails: tuple[str, ...] = ()
    authorized_usernames: tuple[str, ...] = ()

    def covers(self, target: str, subject_kind: Optional[str] = None) -> bool:
        """Match an authorized domain, email, username, IP, phone, or person/company seed."""
        from neesha.resolve.intake import resolve_seed

        if "*" in self.authorized_domains:
            return True

        if subject_kind == "username":
            try:
                normalized = resolve_seed(target, "username")["normalized"].lower()
                allowed = {
                    resolve_seed(u, "username")["normalized"].lower()
                    for u in self.authorized_usernames
                } | {d.strip().lower() for d in self.authorized_domains}
            except ValueError:
                return False
            return normalized in allowed

        if subject_kind == "email" or ("@" in target and subject_kind is None):
            try:
                normalized = resolve_seed(target, "email")["normalized"]
                allowed = {
                    resolve_seed(email, "email")["normalized"]
                    for email in self.authorized_emails
                }
            except ValueError:
                return False
            if normalized in allowed:
                return True
            return False

        if not self.authorized_domains:
            return False
        t = target.strip().lower().rstrip(".")
        for domain in self.authorized_domains:
            d = domain.strip().lower().rstrip(".")
            if t == d or t.endswith("." + d):
                return True
        return False


@dataclass(frozen=True)
class RunCaps:
    max_steps: int
    max_spend_usd: Decimal
    max_wall_secs: int


@dataclass(frozen=True)
class RunState:
    steps_used: int = 0
    spend_used: Decimal = Decimal("0")
    elapsed_secs: float = 0.0


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    reason: str
    reservation: Optional[Reservation] = None

    @property
    def allowed(self) -> bool:
        return self.outcome == "allowed"


class PolicyGate:
    def __init__(
        self,
        engine: sa.Engine,
        ledger: Ledger,
        approval_tiers: frozenset[str] = DEFAULT_APPROVAL_TIERS,
        clock=None,
    ):
        self.engine = engine
        self.ledger = ledger
        self.approval_tiers = approval_tiers
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def authorize(
        self,
        *,
        adapter: AdapterSpec,
        target: str,
        engagement: EngagementView,
        analyst: str,
        caps: RunCaps,
        state: RunState = RunState(),
        estimated_usd=Decimal("0"),
        run_id: Optional[str] = None,
        approved: bool = False,
        subject_kind: Optional[str] = None,
    ) -> Decision:
        estimate = Decimal(str(estimated_usd))
        decision = self._decide(
            adapter=adapter,
            target=target,
            engagement=engagement,
            caps=caps,
            state=state,
            estimate=estimate,
            run_id=run_id,
            approved=approved,
            subject_kind=subject_kind,
        )
        self._log(
            adapter=adapter,
            target=target,
            engagement=engagement,
            analyst=analyst,
            run_id=run_id,
            decision=decision,
            estimate=estimate,
        )
        return decision

    def _decide(
        self,
        *,
        adapter: AdapterSpec,
        target: str,
        engagement: EngagementView,
        caps: RunCaps,
        state: RunState,
        estimate: Decimal,
        run_id: Optional[str],
        approved: bool,
        subject_kind: Optional[str] = None,
    ) -> Decision:
        now = self._clock()

        # 1. Is the engagement in force?
        if engagement.starts_at and now < engagement.starts_at:
            return Decision("denied", f"engagement {engagement.id} has not started")
        if engagement.expires_at and now >= engagement.expires_at:
            return Decision(
                "denied",
                f"engagement {engagement.id} expired at "
                f"{engagement.expires_at.isoformat()}",
            )

        # 2. Is this target covered by the engagement?
        if not engagement.covers(target, subject_kind):
            return Decision(
                "denied",
                f"{target!r} is not an authorized domain, exact email, or username "
                f"for engagement {engagement.id}",
            )

        # 3. Tier D contract-gated stubs are disabled.
        if adapter.tier == "D":
            return Decision(
                "denied",
                f"{adapter.name} is contract-gated (tier D) and disabled",
            )

        # 4. Active scans require active_scan permission; explicit adapter techniques
        #    are checked if declared on the adapter.
        needed = set(adapter.requires_techniques)
        if adapter.collection_mode == "active":
            needed.add(ACTIVE_TECHNIQUE)
        missing = sorted(needed - set(engagement.permitted_techniques))
        if missing:
            return Decision(
                "denied",
                f"engagement {engagement.id} does not permit: {', '.join(missing)}",
            )

        # 5. Has this run used itself up?
        if state.steps_used >= caps.max_steps:
            return Decision("denied", f"run step cap reached ({caps.max_steps})")
        if state.elapsed_secs >= caps.max_wall_secs:
            return Decision(
                "denied", f"run wall-time cap reached ({caps.max_wall_secs}s)"
            )
        if estimate > 0 and state.spend_used + estimate > caps.max_spend_usd:
            return Decision(
                "denied",
                f"run spend cap would be exceeded "
                f"({state.spend_used} + {estimate} > {caps.max_spend_usd})",
            )

        # 6. Optional approval tier check (only when approval_tiers is configured).
        if adapter.tier in self.approval_tiers and not approved:
            return Decision(
                "paused",
                f"{adapter.name} is tier {adapter.tier} and needs analyst approval",
            )

        # 7. Budget reservation for metered calls.
        if estimate > 0:
            try:
                reservation = self.ledger.reserve(
                    adapter.name, estimate, period=period_of(now), run_id=run_id
                )
            except BudgetExceeded as exc:
                return Decision("denied", str(exc))
            except NoBudgetConfigured as exc:
                return Decision("denied", str(exc))
            return Decision("allowed", "within budget and authority", reservation)

        return Decision("allowed", "free source, within authority")

    def _log(
        self,
        *,
        adapter: AdapterSpec,
        target: str,
        engagement: EngagementView,
        analyst: str,
        run_id: Optional[str],
        decision: Decision,
        estimate: Decimal,
    ) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                schema.query_log.insert().values(
                    occurred_at=self._clock(),
                    analyst=analyst,
                    run_id=run_id,
                    engagement_id=engagement.id,
                    authority_basis=engagement.authority_basis,
                    adapter=adapter.name,
                    tier=adapter.tier,
                    target=target,
                    decision=decision.outcome,
                    decision_reason=decision.reason,
                    estimated_usd=estimate if estimate > 0 else None,
                )
            )
