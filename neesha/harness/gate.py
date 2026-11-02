"""The policy gate: the only path to an outbound call.

Every tool call passes through ``PolicyGate.authorize`` before execution. It
checks, in this order:

1. the engagement is in force;
2. the target is one the engagement authorizes;
3. the adapter's tier is permitted by the authority basis;
4. the techniques the adapter needs are permitted by the engagement;
5. the run's own caps — steps, wall time, spend — are not spent;
6. whether this tier needs an analyst to approve;
7. the budget, by taking a reservation.

The order is deliberate. Absolute refusals come first and cost nothing; the
budget reservation comes last because it writes a row and takes a lock, and
there is no point reserving money for a call that was never going to be
allowed. Approval pauses before reserving too: a step waiting on a human
should not be holding budget.

Outcomes are allow, deny, or pause for approval. Every one of them is written
to ``query_log`` with the analyst, authority basis, adapter, tier, target and
cost — the spec's "every query is logged", including the queries that never
happened.

An LLM cannot bypass this because it is not in the call path: the planner
proposes steps, the gate rules on them, and the executor runs only what the
gate approved. A pivot is a new step and takes the same route.
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

# Tier C is manual by definition: never automatic, always a human action.
DEFAULT_APPROVAL_TIERS = frozenset({"C"})

# Techniques that are never implied — an adapter needing one of these must
# find it listed on the engagement.
ACTIVE_TECHNIQUE = "active_scan"


@dataclass(frozen=True)
class AdapterSpec:
    """What the gate needs to know about an adapter.

    Plain data rather than the adapter object, so gate decisions are
    reproducible from a log line and testable without constructing adapters.
    """

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

    def covers(self, target: str) -> bool:
        """Match a domain scope or an independently authorized exact email.

        An empty list authorizes nothing. Defaulting to "all" here would make
        an unconfigured engagement the most permissive one.
        """
        if '@' in target:
            from neesha.resolve.intake import resolve_seed
            try:
                normalized = resolve_seed(target, 'email')['normalized']
                allowed = {resolve_seed(email, 'email')['normalized'] for email in self.authorized_emails}
            except ValueError:
                return False
            return normalized in allowed
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

    # ---- the rules -------------------------------------------------------

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

        # 2. Is this target ours to look at?
        if not engagement.covers(target):
            return Decision(
                "denied",
                f"{target!r} is not an authorized domain or exact email for engagement "
                f"{engagement.id}",
            )

        if '@' in target and adapter.collection_mode != 'third_party_passive':
            return Decision('denied', 'Email-root research permits public-source passive collection only.')

        # 3. Does the authority basis permit this tier?
        if adapter.tier == "D":
            return Decision(
                "denied",
                f"{adapter.name} is contract-gated (tier D) and disabled",
            )
        if adapter.tier == "C" and engagement.authority_basis != "client_engagement":
            return Decision(
                "denied",
                f"{adapter.name} is tier C and requires a client engagement; "
                f"this run's authority is {engagement.authority_basis}",
            )

        # 4. Does the engagement permit the techniques this adapter needs?
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

        # 6. Does a human have to say yes first? Pause before reserving, so a
        #    step waiting on approval is not sitting on budget.
        if adapter.tier in self.approval_tiers and not approved:
            return Decision(
                "paused",
                f"{adapter.name} is tier {adapter.tier} and needs analyst approval",
            )

        # 7. Finally, the money.
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

    # ---- logging ---------------------------------------------------------

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
        """Write the decision to the append-only query log.

        In its own transaction, on purpose: a denial has no transaction to
        join, and the record of an attempt should survive whatever happened
        to the work it was attempting.
        """
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
