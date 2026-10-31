"""Ledger tests.

The accounting rules are checked on SQLite. The concurrency guarantee is
checked on Postgres, because row locks are what provides it and SQLite
silently ignores ``FOR UPDATE`` — a concurrency test passing on SQLite would
be proving nothing about the deployed system.
"""
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import pytest
import sqlalchemy as sa

from neesha.db import schema
from neesha.ledger.ledger import (
    BudgetExceeded,
    Ledger,
    LedgerError,
    NoBudgetConfigured,
    period_of,
)

PERIOD = "2026-10"


@pytest.fixture
def ledger(engine):
    return Ledger(engine)


# ---- configuration and accounting ---------------------------------------


def test_no_budget_means_no_spending(ledger):
    """An unconfigured budget must not read as an unlimited one."""
    with pytest.raises(NoBudgetConfigured):
        ledger.reserve("hunter", "1.00", period=PERIOD)


def test_reserve_within_cap(ledger):
    ledger.set_cap("100.00", period=PERIOD)
    r = ledger.reserve("hunter", "1.50", period=PERIOD)
    assert r.estimated_usd == Decimal("1.5000")
    assert ledger.summary(PERIOD).committed_usd == Decimal("1.5000")


def test_reservation_commits_its_estimate_before_settling(ledger):
    """An open reservation must count, or two callers both 'fit'."""
    ledger.set_cap("10.00", period=PERIOD)
    ledger.reserve("hunter", "9.00", period=PERIOD)
    with pytest.raises(BudgetExceeded):
        ledger.reserve("shodan", "2.00", period=PERIOD)


def test_settling_replaces_the_estimate_with_the_actual(ledger):
    ledger.set_cap("10.00", period=PERIOD)
    r = ledger.reserve("hunter", "5.00", period=PERIOD)
    ledger.settle(r.id, "1.25")
    assert ledger.summary(PERIOD).committed_usd == Decimal("1.2500")


def test_settling_above_the_estimate_is_recorded_honestly(ledger):
    """Actual cost can exceed the estimate; the ledger records truth rather
    than clamping it, and the next reservation sees the real number."""
    ledger.set_cap("10.00", period=PERIOD)
    r = ledger.reserve("hunter", "1.00", period=PERIOD)
    ledger.settle(r.id, "9.50")
    assert ledger.summary(PERIOD).committed_usd == Decimal("9.5000")
    with pytest.raises(BudgetExceeded):
        ledger.reserve("hunter", "1.00", period=PERIOD)


def test_releasing_gives_the_money_back(ledger):
    ledger.set_cap("10.00", period=PERIOD)
    r = ledger.reserve("hunter", "9.00", period=PERIOD)
    ledger.release(r.id)
    assert ledger.summary(PERIOD).committed_usd == Decimal("0.0000")
    assert ledger.reserve("shodan", "9.00", period=PERIOD)


def test_a_reservation_cannot_be_settled_twice(ledger):
    ledger.set_cap("10.00", period=PERIOD)
    r = ledger.reserve("hunter", "1.00", period=PERIOD)
    ledger.settle(r.id, "1.00")
    with pytest.raises(LedgerError):
        ledger.settle(r.id, "1.00")


def test_a_released_reservation_cannot_be_settled(ledger):
    ledger.set_cap("10.00", period=PERIOD)
    r = ledger.reserve("hunter", "1.00", period=PERIOD)
    ledger.release(r.id)
    with pytest.raises(LedgerError):
        ledger.settle(r.id, "1.00")


def test_negative_reservations_are_refused(ledger):
    ledger.set_cap("10.00", period=PERIOD)
    with pytest.raises(LedgerError):
        ledger.reserve("hunter", "-5.00", period=PERIOD)


def test_exact_cap_is_allowed_but_one_cent_more_is_not(ledger):
    ledger.set_cap("10.00", period=PERIOD)
    ledger.reserve("hunter", "10.00", period=PERIOD)
    with pytest.raises(BudgetExceeded):
        ledger.reserve("hunter", "0.0001", period=PERIOD)


# ---- fixed costs --------------------------------------------------------


def test_fixed_costs_reduce_what_is_available(ledger):
    """Hosting is inside the cap, so the variable budget must reflect it."""
    ledger.set_cap("100.00", period=PERIOD)
    ledger.record_fixed_cost("hosting", "20.00", period=PERIOD)
    summary = ledger.summary(PERIOD)
    assert summary.committed_usd == Decimal("20.0000")
    assert summary.remaining_usd == Decimal("80.0000")


def test_fixed_costs_can_exhaust_the_budget(ledger):
    ledger.set_cap("100.00", period=PERIOD)
    ledger.record_fixed_cost("hosting", "100.00", period=PERIOD)
    with pytest.raises(BudgetExceeded):
        ledger.reserve("hunter", "0.01", period=PERIOD)


# ---- sub-budgets --------------------------------------------------------


def test_adapter_sub_budget_caps_one_source(ledger):
    ledger.set_cap("100.00", period=PERIOD)
    ledger.set_cap("5.00", period=PERIOD, adapter="hunter")
    ledger.reserve("hunter", "5.00", period=PERIOD)
    with pytest.raises(BudgetExceeded) as exc:
        ledger.reserve("hunter", "1.00", period=PERIOD)
    assert exc.value.scope == "hunter"
    # Other adapters still have the global headroom.
    assert ledger.reserve("shodan", "10.00", period=PERIOD)


def test_sub_budget_cannot_exceed_the_global_cap(ledger):
    """A generous sub-budget does not widen the monthly cap."""
    ledger.set_cap("10.00", period=PERIOD)
    ledger.set_cap("999.00", period=PERIOD, adapter="hunter")
    with pytest.raises(BudgetExceeded) as exc:
        ledger.reserve("hunter", "50.00", period=PERIOD)
    assert exc.value.scope == "*"


# ---- alerting -----------------------------------------------------------


def test_alert_thresholds(ledger):
    ledger.set_cap("100.00", period=PERIOD)
    assert ledger.summary(PERIOD).alerts == []
    ledger.reserve("hunter", "75.00", period=PERIOD)
    assert ledger.summary(PERIOD).alerts == ["75%"]
    ledger.reserve("shodan", "15.00", period=PERIOD)
    assert ledger.summary(PERIOD).alerts == ["75%", "90%"]


def test_exhausted_at_one_hundred_percent(ledger):
    ledger.set_cap("10.00", period=PERIOD)
    assert not ledger.summary(PERIOD).exhausted
    ledger.reserve("hunter", "10.00", period=PERIOD)
    assert ledger.summary(PERIOD).exhausted


def test_summary_breaks_down_by_adapter(ledger):
    ledger.set_cap("100.00", period=PERIOD)
    ledger.reserve("hunter", "3.00", period=PERIOD)
    ledger.reserve("shodan", "7.00", period=PERIOD)
    by = ledger.summary(PERIOD).by_adapter
    assert by == {"hunter": Decimal("3.0000"), "shodan": Decimal("7.0000")}


def test_periods_are_independent(ledger):
    ledger.set_cap("10.00", period="2026-10")
    ledger.set_cap("10.00", period="2026-11")
    ledger.reserve("hunter", "10.00", period="2026-10")
    assert ledger.reserve("hunter", "10.00", period="2026-11")


def test_period_of_formats_year_month():
    from datetime import datetime, timezone

    assert period_of(datetime(2026, 3, 9, tzinfo=timezone.utc)) == "2026-03"


# ---- the concurrency guarantee, on Postgres -----------------------------


@pytest.mark.parametrize("workers,each,cap,expected", [(20, "1.00", "10.00", 10)])
def test_cap_holds_under_concurrency(pg_engine, workers, each, cap, expected):
    """The core spend-safety claim: N workers racing one cap cannot
    collectively reserve more than the cap allows.

    Postgres only. SQLite ignores SELECT ... FOR UPDATE, so this passing
    there would say nothing about the deployed system.
    """
    ledger = Ledger(pg_engine)
    ledger.set_cap(cap, period=PERIOD)

    barrier = threading.Barrier(workers)
    granted: list[Decimal] = []
    refused = 0
    lock = threading.Lock()

    def attempt(_i):
        nonlocal refused
        barrier.wait()  # maximize contention on the budget row
        try:
            r = ledger.reserve("hunter", each, period=PERIOD)
        except BudgetExceeded:
            with lock:
                refused += 1
            return
        with lock:
            granted.append(r.estimated_usd)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(attempt, range(workers)))

    assert len(granted) == expected, f"expected {expected} grants, got {len(granted)}"
    assert refused == workers - expected
    assert sum(granted) == Decimal(cap)
    # And the ledger agrees with what the workers were told.
    assert ledger.summary(PERIOD).committed_usd == Decimal(cap)


def test_concurrent_mixed_estimates_never_overspend(pg_engine):
    """Uneven estimates must also not overshoot, even though the number of
    winners is then not fixed."""
    ledger = Ledger(pg_engine)
    ledger.set_cap("10.00", period=PERIOD)

    amounts = ["0.50", "3.00", "7.00", "2.00", "5.00", "1.00", "4.00", "6.00"]
    barrier = threading.Barrier(len(amounts))
    granted: list[Decimal] = []
    lock = threading.Lock()

    def attempt(amount):
        barrier.wait()
        try:
            r = ledger.reserve("hunter", amount, period=PERIOD)
        except BudgetExceeded:
            return
        with lock:
            granted.append(r.estimated_usd)

    with ThreadPoolExecutor(max_workers=len(amounts)) as pool:
        list(pool.map(attempt, amounts))

    assert sum(granted) <= Decimal("10.00")
    assert ledger.summary(PERIOD).committed_usd == sum(granted)
    assert granted, "at least one reservation should have fitted"


def test_concurrent_sub_budget_also_holds(pg_engine):
    ledger = Ledger(pg_engine)
    ledger.set_cap("1000.00", period=PERIOD)
    ledger.set_cap("5.00", period=PERIOD, adapter="hunter")

    barrier = threading.Barrier(12)
    granted: list[Decimal] = []
    lock = threading.Lock()

    def attempt(_i):
        barrier.wait()
        try:
            r = ledger.reserve("hunter", "1.00", period=PERIOD)
        except BudgetExceeded:
            return
        with lock:
            granted.append(r.estimated_usd)

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(attempt, range(12)))

    assert sum(granted) == Decimal("5.00")


def test_ledger_rows_are_consistent_after_a_race(pg_engine):
    """No partial rows: every row is either a counted reservation or absent."""
    ledger = Ledger(pg_engine)
    ledger.set_cap("4.00", period=PERIOD)

    barrier = threading.Barrier(10)

    def attempt(_i):
        barrier.wait()
        try:
            ledger.reserve("hunter", "1.00", period=PERIOD)
        except BudgetExceeded:
            pass

    with ThreadPoolExecutor(max_workers=10) as pool:
        list(pool.map(attempt, range(10)))

    with pg_engine.connect() as conn:
        rows = conn.execute(
            sa.select(schema.ledger.c.state, schema.ledger.c.estimated_usd).where(
                schema.ledger.c.period == PERIOD
            )
        ).all()
    assert len(rows) == 4
    assert all(state == "reserved" for state, _ in rows)
    assert sum(amount for _, amount in rows) == Decimal("4.00")
