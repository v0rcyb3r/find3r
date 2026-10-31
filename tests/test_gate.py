"""Policy gate tests.

The gate is the only path to an outbound call, so these cover each refusal
reason, the ordering guarantees that keep budget from being consumed by calls
that were never going to run, and the requirement that every decision —
including the refusals — reaches the query log.
"""
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest
import sqlalchemy as sa

from neesha.db import schema
from neesha.harness.gate import (
    AdapterSpec,
    EngagementView,
    PolicyGate,
    RunCaps,
    RunState,
)
from neesha.ledger.ledger import Ledger

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
PERIOD = "2026-10"

FREE = AdapterSpec(name="crt.sh", tier="A")
METERED = AdapterSpec(name="hunter", tier="B")
GATED = AdapterSpec(
    name="sherlock", tier="C", requires_techniques=frozenset({"username_enum"})
)
CONTRACT = AdapterSpec(name="zoominfo", tier="D")
ACTIVE = AdapterSpec(name="portscan", tier="A", collection_mode="active")

CAPS = RunCaps(max_steps=50, max_spend_usd=Decimal("5.00"), max_wall_secs=600)


@pytest.fixture
def ledger(engine):
    led = Ledger(engine)
    led.set_cap("100.00", period=PERIOD)
    return led


@pytest.fixture
def gate(engine, ledger):
    return PolicyGate(engine, ledger, clock=lambda: NOW)


def prospect(**kw) -> EngagementView:
    base = dict(
        id="eng-1",
        authority_basis="prospect_company",
        authorized_domains=("acme.com",),
        starts_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=29),
    )
    base.update(kw)
    return EngagementView(**base)


def client(**kw) -> EngagementView:
    base = dict(
        id="eng-client",
        authority_basis="client_engagement",
        permitted_techniques=frozenset({"username_enum", "active_scan"}),
    )
    base.update(kw)
    return prospect(**base)


def ask(gate, adapter=FREE, engagement=None, target="acme.com", **kw):
    return gate.authorize(
        adapter=adapter,
        target=target,
        engagement=engagement or prospect(),
        analyst="analyst@vorcyber",
        caps=kw.pop("caps", CAPS),
        **kw,
    )


# ---- the happy paths ----------------------------------------------------


def test_free_source_on_a_prospect_is_allowed(gate):
    d = ask(gate)
    assert d.allowed and d.reservation is None


def test_metered_source_is_allowed_and_reserves(gate):
    d = ask(gate, METERED, estimated_usd="0.50")
    assert d.allowed
    assert d.reservation.estimated_usd == Decimal("0.5000")


def test_subdomain_of_an_authorized_domain_is_covered(gate):
    assert ask(gate, target="mail.acme.com").allowed


# ---- engagement window -------------------------------------------------


def test_engagement_not_yet_started_is_denied(gate):
    d = ask(gate, engagement=prospect(starts_at=NOW + timedelta(days=1)))
    assert d.outcome == "denied" and "has not started" in d.reason


def test_expired_engagement_is_denied(gate):
    d = ask(gate, engagement=prospect(expires_at=NOW - timedelta(seconds=1)))
    assert d.outcome == "denied" and "expired" in d.reason


# ---- target authorization ----------------------------------------------


def test_unlisted_target_is_denied(gate):
    d = ask(gate, target="othercorp.com")
    assert d.outcome == "denied" and "not an authorized domain" in d.reason


def test_empty_domain_list_authorizes_nothing(gate):
    """An unconfigured engagement must not be the most permissive one."""
    d = ask(gate, engagement=prospect(authorized_domains=()))
    assert d.outcome == "denied"


def test_suffix_confusion_is_not_a_match(gate):
    """notacme.com must not match acme.com."""
    assert ask(gate, target="notacme.com").outcome == "denied"


def test_target_matching_ignores_case_and_trailing_dot(gate):
    assert ask(gate, target="ACME.com.").allowed


# ---- tier vs authority -------------------------------------------------


def test_contract_gated_tier_d_is_always_denied(gate):
    d = ask(gate, CONTRACT, engagement=client())
    assert d.outcome == "denied" and "contract-gated" in d.reason


def test_tier_c_is_denied_on_prospect_authority(gate):
    """Username enumeration against a prospect is the case this blocks."""
    d = ask(
        gate,
        GATED,
        engagement=prospect(permitted_techniques=frozenset({"username_enum"})),
    )
    assert d.outcome == "denied" and "requires a client engagement" in d.reason


def test_tier_c_pauses_for_approval_under_a_client_engagement(gate):
    d = ask(gate, GATED, engagement=client())
    assert d.outcome == "paused" and "approval" in d.reason


def test_tier_c_runs_once_approved(gate):
    d = ask(gate, GATED, engagement=client(), approved=True)
    assert d.allowed


# ---- techniques --------------------------------------------------------


def test_missing_technique_is_denied(gate):
    d = ask(
        gate,
        GATED,
        engagement=client(permitted_techniques=frozenset()),
        approved=True,
    )
    assert d.outcome == "denied" and "does not permit" in d.reason


def test_active_mode_requires_active_scan_permission(gate):
    d = ask(gate, ACTIVE)
    assert d.outcome == "denied" and "active_scan" in d.reason


def test_active_mode_allowed_when_the_engagement_permits_it(gate):
    assert ask(gate, ACTIVE, engagement=client()).allowed


# ---- run caps ----------------------------------------------------------


def test_step_cap_stops_the_run(gate):
    d = ask(gate, state=RunState(steps_used=50))
    assert d.outcome == "denied" and "step cap" in d.reason


def test_wall_time_cap_stops_the_run(gate):
    d = ask(gate, state=RunState(elapsed_secs=601))
    assert d.outcome == "denied" and "wall-time" in d.reason


def test_run_spend_cap_is_separate_from_the_monthly_cap(gate):
    """A single run cannot drain the month even when the month has room."""
    d = ask(
        gate,
        METERED,
        estimated_usd="1.00",
        state=RunState(spend_used=Decimal("4.50")),
    )
    assert d.outcome == "denied" and "run spend cap" in d.reason


# ---- budget ------------------------------------------------------------


def test_monthly_cap_refusal_is_a_denial(gate, ledger):
    ledger.reserve("other", "100.00", period=PERIOD)
    d = ask(gate, METERED, estimated_usd="0.01")
    assert d.outcome == "denied" and "cap" in d.reason


def test_unconfigured_budget_denies_metered_calls(engine):
    """No cap configured must not mean unlimited."""
    gate = PolicyGate(engine, Ledger(engine), clock=lambda: NOW)
    d = ask(gate, METERED, estimated_usd="0.01")
    assert d.outcome == "denied" and "no budget configured" in d.reason.lower()


def test_free_sources_still_run_when_the_budget_is_gone(gate, ledger):
    """Tier A costs nothing, so an exhausted budget must not stop recon."""
    ledger.reserve("other", "100.00", period=PERIOD)
    assert ask(gate).allowed


# ---- ordering: refusals must not consume budget ------------------------


def test_a_denied_call_reserves_nothing(gate, ledger):
    ask(gate, METERED, target="othercorp.com", estimated_usd="5.00")
    assert ledger.summary(PERIOD).committed_usd == Decimal("0.0000")


def test_a_paused_call_reserves_nothing(engine, ledger):
    """A step waiting on a human must not sit on budget."""
    gate = PolicyGate(
        engine, ledger, approval_tiers=frozenset({"B", "C"}), clock=lambda: NOW
    )
    d = ask(gate, METERED, estimated_usd="5.00")
    assert d.outcome == "paused"
    assert ledger.summary(PERIOD).committed_usd == Decimal("0.0000")


# ---- logging -----------------------------------------------------------


def rows(engine):
    with engine.connect() as conn:
        return conn.execute(
            sa.select(
                schema.query_log.c.adapter,
                schema.query_log.c.decision,
                schema.query_log.c.target,
                schema.query_log.c.authority_basis,
                schema.query_log.c.analyst,
                schema.query_log.c.tier,
                schema.query_log.c.estimated_usd,
            ).order_by(schema.query_log.c.id)
        ).all()


def test_allowed_calls_are_logged(gate, engine):
    ask(gate, METERED, estimated_usd="0.25")
    (row,) = rows(engine)
    assert row.adapter == "hunter"
    assert row.decision == "allowed"
    assert row.target == "acme.com"
    assert row.analyst == "analyst@vorcyber"
    assert row.tier == "B"
    assert row.estimated_usd == Decimal("0.2500")


def test_denied_calls_are_logged_too(gate, engine):
    """The queries that never happened are the interesting ones in a review."""
    ask(gate, target="othercorp.com")
    (row,) = rows(engine)
    assert row.decision == "denied"
    assert row.target == "othercorp.com"


def test_paused_calls_are_logged(gate, engine):
    ask(gate, GATED, engagement=client())
    (row,) = rows(engine)
    assert row.decision == "paused"


def test_every_decision_appears_exactly_once(gate, engine):
    ask(gate)
    ask(gate, METERED, estimated_usd="0.10")
    ask(gate, target="nope.com")
    ask(gate, CONTRACT)
    logged = rows(engine)
    assert len(logged) == 4
    assert [r.decision for r in logged] == [
        "allowed",
        "allowed",
        "denied",
        "denied",
    ]


def test_log_records_the_authority_the_call_ran_under(gate, engine):
    ask(gate, GATED, engagement=client(), approved=True)
    (row,) = rows(engine)
    assert row.authority_basis == "client_engagement"
