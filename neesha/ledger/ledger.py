"""The budget ledger: reserve before spending, settle after.

Spend safety rests on one invariant: **no outbound metered call happens
without a committed reservation that fitted inside the cap at the moment it
was taken.** Reservations and settlements are summed together, so two workers
racing the same remaining dollar cannot both win.

The serialization point is a row lock on the matching ``budget`` row. Every
reservation for a period contends on the same row for the global cap, which
turns concurrent reservation into a queue. This is the reason the deployment
target is Postgres: ``SELECT ... FOR UPDATE`` is a no-op on SQLite, so on
SQLite the guarantee degrades to whatever its transaction serialization
gives you. The concurrency tests that prove the cap holds therefore run
against Postgres and skip elsewhere.

Accounting rules:

- A ``reserved`` row commits its *estimate*. A ``settled`` row commits its
  *actual*. A ``released`` row commits nothing.
- Fixed costs (hosting, subscriptions) are settled rows, so the variable
  budget reflects what is genuinely left rather than the headline cap.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

import sqlalchemy as sa

from neesha.db import schema

CENTS = Decimal("0.0001")

# Fractions of the cap at which the operator is warned, and the point at
# which reservations stop entirely.
WARN_THRESHOLDS = (Decimal("0.75"), Decimal("0.90"))

GLOBAL = "*"


class LedgerError(Exception):
    """Base class for spend-control failures."""


class NoBudgetConfigured(LedgerError):
    """No cap exists for the period, so nothing may be spent.

    Deliberately fatal rather than permissive: an unconfigured budget must
    not read as an unlimited one.
    """


class BudgetExceeded(LedgerError):
    """The reservation would have taken committed spend past a cap."""

    def __init__(self, message: str, *, scope: str, cap: Decimal, committed: Decimal):
        super().__init__(message)
        self.scope = scope
        self.cap = cap
        self.committed = committed


def _money(value) -> Decimal:
    return Decimal(str(value)).quantize(CENTS)


def period_of(when: Optional[datetime] = None) -> str:
    when = when or datetime.now(timezone.utc)
    return f"{when.year:04d}-{when.month:02d}"


@dataclass(frozen=True)
class Reservation:
    id: int
    period: str
    adapter: str
    estimated_usd: Decimal
    run_id: Optional[str] = None


@dataclass(frozen=True)
class SpendSummary:
    period: str
    cap_usd: Decimal
    committed_usd: Decimal
    by_adapter: dict[str, Decimal] = field(default_factory=dict)

    @property
    def remaining_usd(self) -> Decimal:
        return max(Decimal("0"), self.cap_usd - self.committed_usd)

    @property
    def fraction_used(self) -> Decimal:
        if self.cap_usd <= 0:
            return Decimal("1")
        return (self.committed_usd / self.cap_usd).quantize(Decimal("0.0001"))

    @property
    def alerts(self) -> list[str]:
        """Thresholds crossed, for the 75% / 90% warnings."""
        used = self.fraction_used
        return [f"{int(t * 100)}%" for t in WARN_THRESHOLDS if used >= t]

    @property
    def exhausted(self) -> bool:
        return self.committed_usd >= self.cap_usd


class Ledger:
    def __init__(self, engine: sa.Engine):
        self.engine = engine

    # ---- configuration ---------------------------------------------------

    def set_cap(self, cap_usd, period: Optional[str] = None, adapter: str = GLOBAL) -> None:
        """Set the monthly cap, or a per-adapter sub-budget."""
        period = period or period_of()
        table = schema.budget
        with self.engine.begin() as conn:
            existing = conn.execute(
                sa.select(table.c.cap_usd).where(
                    table.c.period == period, table.c.adapter == adapter
                )
            ).first()
            if existing is None:
                conn.execute(
                    table.insert().values(
                        period=period, adapter=adapter, cap_usd=_money(cap_usd)
                    )
                )
            else:
                conn.execute(
                    table.update()
                    .where(table.c.period == period, table.c.adapter == adapter)
                    .values(cap_usd=_money(cap_usd))
                )

    def record_fixed_cost(
        self, adapter: str, usd, period: Optional[str] = None
    ) -> None:
        """Record hosting or a subscription as already-spent for the period.

        Settled at once, so the variable budget reflects what is actually
        left rather than the headline cap.
        """
        period = period or period_of()
        now = datetime.now(timezone.utc)
        with self.engine.begin() as conn:
            conn.execute(
                schema.ledger.insert().values(
                    period=period,
                    adapter=adapter,
                    kind="fixed_cost",
                    estimated_usd=_money(usd),
                    actual_usd=_money(usd),
                    state="settled",
                    created_at=now,
                    settled_at=now,
                )
            )

    # ---- the critical section -------------------------------------------

    def reserve(
        self,
        adapter: str,
        estimated_usd,
        run_id: Optional[str] = None,
        period: Optional[str] = None,
    ) -> Reservation:
        """Commit an estimate against the cap, or refuse.

        Raises BudgetExceeded if the reservation would not fit, and
        NoBudgetConfigured if no cap is set for the period.
        """
        period = period or period_of()
        estimate = _money(estimated_usd)
        if estimate < 0:
            raise LedgerError("a reservation cannot be negative")

        with self.engine.begin() as conn:
            # Lock in a fixed order — global cap, then the sub-budget — so
            # concurrent reservers for different adapters cannot deadlock by
            # grabbing the same two rows in opposite orders.
            global_cap = self._lock_cap(conn, period, GLOBAL)
            if global_cap is None:
                raise NoBudgetConfigured(
                    f"no budget configured for {period}; set a cap before spending"
                )
            adapter_cap = (
                self._lock_cap(conn, period, adapter) if adapter != GLOBAL else None
            )

            committed = self._committed(conn, period)
            if committed + estimate > global_cap:
                raise BudgetExceeded(
                    f"monthly cap for {period} would be exceeded: "
                    f"{committed} committed + {estimate} > {global_cap}",
                    scope=GLOBAL,
                    cap=global_cap,
                    committed=committed,
                )

            if adapter_cap is not None:
                used = self._committed(conn, period, adapter)
                if used + estimate > adapter_cap:
                    raise BudgetExceeded(
                        f"sub-budget for {adapter} in {period} would be exceeded: "
                        f"{used} committed + {estimate} > {adapter_cap}",
                        scope=adapter,
                        cap=adapter_cap,
                        committed=used,
                    )

            row_id = conn.execute(
                schema.ledger.insert()
                .values(
                    period=period,
                    adapter=adapter,
                    run_id=run_id,
                    kind="reservation",
                    estimated_usd=estimate,
                    state="reserved",
                    created_at=datetime.now(timezone.utc),
                )
                .returning(schema.ledger.c.id)
            ).scalar_one()

        return Reservation(
            id=row_id,
            period=period,
            adapter=adapter,
            estimated_usd=estimate,
            run_id=run_id,
        )

    def settle(self, reservation_id: int, actual_usd) -> None:
        """Replace an estimate with what the call actually cost."""
        actual = _money(actual_usd)
        with self.engine.begin() as conn:
            updated = conn.execute(
                schema.ledger.update()
                .where(
                    schema.ledger.c.id == reservation_id,
                    schema.ledger.c.state == "reserved",
                )
                .values(
                    kind="settlement",
                    actual_usd=actual,
                    state="settled",
                    settled_at=datetime.now(timezone.utc),
                )
            ).rowcount
        if not updated:
            raise LedgerError(
                f"reservation {reservation_id} is not open; it was already "
                "settled or released"
            )

    def release(self, reservation_id: int) -> None:
        """Give back an unspent reservation, e.g. after a failed call."""
        with self.engine.begin() as conn:
            updated = conn.execute(
                schema.ledger.update()
                .where(
                    schema.ledger.c.id == reservation_id,
                    schema.ledger.c.state == "reserved",
                )
                .values(state="released", settled_at=datetime.now(timezone.utc))
            ).rowcount
        if not updated:
            raise LedgerError(
                f"reservation {reservation_id} is not open; nothing to release"
            )

    # ---- reporting -------------------------------------------------------

    def summary(self, period: Optional[str] = None) -> SpendSummary:
        period = period or period_of()
        with self.engine.connect() as conn:
            cap = conn.execute(
                sa.select(schema.budget.c.cap_usd).where(
                    schema.budget.c.period == period,
                    schema.budget.c.adapter == GLOBAL,
                )
            ).scalar()
            committed = self._committed(conn, period)
            rows = conn.execute(
                sa.select(
                    schema.ledger.c.adapter,
                    sa.func.sum(self._committed_expr()),
                )
                .where(
                    schema.ledger.c.period == period,
                    schema.ledger.c.state != "released",
                )
                .group_by(schema.ledger.c.adapter)
            ).all()
        return SpendSummary(
            period=period,
            cap_usd=_money(cap) if cap is not None else Decimal("0"),
            committed_usd=committed,
            by_adapter={adapter: _money(total) for adapter, total in rows},
        )

    # ---- internals -------------------------------------------------------

    @staticmethod
    def _lock_cap(conn, period: str, adapter: str) -> Optional[Decimal]:
        """Read a cap under a row lock.

        ``with_for_update`` is what serializes concurrent reservers. It is
        silently ignored by SQLite, which is why the concurrency guarantee is
        stated for Postgres only.
        """
        stmt = sa.select(schema.budget.c.cap_usd).where(
            schema.budget.c.period == period, schema.budget.c.adapter == adapter
        )
        if conn.dialect.name != "sqlite":
            stmt = stmt.with_for_update()
        value = conn.execute(stmt).scalar()
        return _money(value) if value is not None else None

    @staticmethod
    def _committed_expr():
        """Reserved rows commit their estimate; settled rows their actual."""
        return sa.case(
            (schema.ledger.c.state == "settled", schema.ledger.c.actual_usd),
            else_=schema.ledger.c.estimated_usd,
        )

    @classmethod
    def _committed(cls, conn, period: str, adapter: Optional[str] = None) -> Decimal:
        where = [
            schema.ledger.c.period == period,
            schema.ledger.c.state != "released",
        ]
        if adapter is not None:
            where.append(schema.ledger.c.adapter == adapter)
        total = conn.execute(
            sa.select(sa.func.coalesce(sa.func.sum(cls._committed_expr()), 0)).where(
                *where
            )
        ).scalar()
        return _money(total or 0)
