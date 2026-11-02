"""The run loop: one pass of the intelligence cycle.

Direction (PIRs) → Collection (gated steps) → Processing (typed facts) →
and then a report that states what was learned, what was skipped, and what
could not be answered at all.

The last part is the point. A run that quietly returns less than it was asked
for is worse than one that says "PIR-2 partial: no org data collected",
because an analyst can act on a known gap and cannot act on an unknown one.
Stop reasons and per-requirement gaps are both first-class outputs here, not
log lines.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Optional, Sequence
from uuid import uuid4

import sqlalchemy as sa

from neesha.adapters import registry
from neesha.db import schema
from neesha.harness.executor import Executor, StepResult
from neesha.harness.gate import PolicyGate, RunCaps, RunState
from neesha.harness.plan import PIR, Plan, build_plan, expand_templates
from neesha.harness.repository import Repository
from neesha.ledger.ledger import Ledger

STOP_COMPLETE = "complete"
STOP_STEP_CAP = "step_cap"
STOP_SPEND = "budget"
STOP_WALL_TIME = "wall_time"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class RunReport:
    run_id: str
    company: str
    company_id: str
    status: str
    stop_reason: str
    steps: list[StepResult] = field(default_factory=list)
    pirs: list[PIR] = field(default_factory=list)
    spend_usd: Decimal = Decimal("0")
    skipped: list[dict] = field(default_factory=list)
    estimated_usd: Decimal = Decimal("0")
    subject_kind: str = "company"

    @property
    def facts_written(self) -> int:
        return sum(s.facts_written for s in self.steps)

    @property
    def answered(self) -> list[PIR]:
        return [p for p in self.pirs if p.status == "answered"]

    @property
    def gaps(self) -> list[PIR]:
        return [p for p in self.pirs if p.status in ("partial", "unanswerable")]


def execute_run(
    *,
    engine: sa.Engine,
    ledger: Ledger,
    gate: PolicyGate,
    company: str,
    engagement,
    analyst: str,
    pir_templates: Sequence[str] = ("attack-surface",),
    caps: Optional[RunCaps] = None,
    adapters: Optional[dict[str, Any]] = None,
    tiers: Optional[set[str]] = None,
    sources: Optional[set[str]] = None,
    progress: Optional[Callable[[dict], None]] = None,
    subject_kind: str = "domain",
) -> RunReport:
    """Run one cycle and return what it learned and what it did not.

    ``adapters`` lets a caller inject pre-built instances; otherwise the
    registry builds them. That is how the tests drive real adapter code
    against fixture payloads without touching the network.
    """
    caps = caps or RunCaps(
        max_steps=25, max_spend_usd=Decimal("1.00"), max_wall_secs=600
    )

    # Validate direction before creating a run that could be left running.
    if subject_kind == 'email' and tuple(pir_templates) == ('attack-surface',):
        pir_templates = ('email-public-presence',)
    pirs = expand_templates(pir_templates)
    if subject_kind not in ('domain', 'company', 'email'):
        raise ValueError('Only domain/company and exact-email runs are connected.')
    if subject_kind == 'email':
        from neesha.resolve.intake import resolve_seed
        company = resolve_seed(company, 'email')['normalized']
    plan = build_plan(pirs, company, entity_kind=subject_kind, tiers=tiers, sources=sources)

    company_id = (Repository.ensure_email(engine, company) if subject_kind == 'email'
                  else Repository.ensure_company(engine, company))
    run_id = uuid4().hex
    started = _now()
    monotonic_start = time.monotonic()

    with engine.begin() as conn:
        conn.execute(
            schema.run.insert().values(
                id=run_id,
                engagement_id=engagement.id,
                company_id=company_id,
                analyst=analyst,
                status="running",
                max_steps=caps.max_steps,
                max_spend_usd=caps.max_spend_usd,
                max_wall_secs=caps.max_wall_secs,
                started_at=started,
            )
        )

    repo = Repository(engine, company_id=company_id, run_id=run_id, subject_kind=subject_kind)
    executor = Executor(
        gate=gate,
        ledger=ledger,
        repository=repo,
        engagement=engagement,
        analyst=analyst,
        caps=caps,
    )

    steps: list[StepResult] = []
    skipped: list[dict] = list(plan.skipped)
    state = RunState()
    stop_reason = STOP_COMPLETE

    for step in plan.steps:
        elapsed = time.monotonic() - monotonic_start
        halt = _stop_condition(state, caps, elapsed)
        if halt:
            stop_reason = halt
            # Everything from here on is explicitly unrun, with a reason.
            skipped.extend(
                {"adapter": s.adapter_name, "reason": halt}
                for s in plan.steps[plan.steps.index(step) :]
            )
            break

        adapter = (
            adapters.get(step.adapter_name)
            if adapters
            else registry.build(step.adapter_name)
        )
        if adapter is None:
            skipped.append(
                {"adapter": step.adapter_name, "reason": "adapter unavailable"}
            )
            continue

        if progress:
            progress({"current_source": step.adapter_name, "completed": len(steps),
                      "total": len(plan.steps)})
        result = executor.execute(
            adapter,
            step.request,
            state=RunState(
                steps_used=state.steps_used,
                spend_used=state.spend_used,
                elapsed_secs=elapsed,
            ),
        )
        steps.append(result)
        if progress:
            progress({"current_source": step.adapter_name, "completed": len(steps),
                      "total": len(plan.steps), "last_outcome": result.outcome})
        state = RunState(
            steps_used=state.steps_used + 1,
            spend_used=state.spend_used + result.cost_usd,
            elapsed_secs=time.monotonic() - monotonic_start,
        )
        if not result.productive:
            skipped.append({"adapter": result.adapter, "reason": result.reason})

    _resolve_pirs(engine, plan, company_id, run_id, steps)
    _persist_pirs(engine, run_id, plan.pirs)

    status = "complete" if stop_reason == STOP_COMPLETE else "stopped"
    with engine.begin() as conn:
        conn.execute(
            schema.run.update()
            .where(schema.run.c.id == run_id)
            .values(
                status=status,
                stop_reason=stop_reason,
                skipped=skipped,
                ended_at=_now(),
            )
        )

    return RunReport(
        run_id=run_id,
        company=company,
        company_id=company_id,
        status=status,
        stop_reason=stop_reason,
        steps=steps,
        pirs=plan.pirs,
        spend_usd=state.spend_used,
        skipped=skipped,
        estimated_usd=plan.estimated_total_usd,
        subject_kind=subject_kind,
    )


def _stop_condition(
    state: RunState, caps: RunCaps, elapsed: float
) -> Optional[str]:
    if state.steps_used >= caps.max_steps:
        return STOP_STEP_CAP
    if state.spend_used >= caps.max_spend_usd:
        return STOP_SPEND
    if elapsed >= caps.max_wall_secs:
        return STOP_WALL_TIME
    return None


def _resolve_pirs(
    engine: sa.Engine, plan: Plan, company_id: str, run_id: str, steps: list[StepResult]
) -> None:
    """Mark each requirement answered, partial, or unanswerable.

    Resolution is from what is actually in the fact table, not from whether a
    step ran: an adapter that returned nothing useful leaves the requirement
    unanswered, and should say so.
    """
    collected: set[str] = set()
    for step in steps:
        collected |= set(step.attributes)

    failure_reasons = {
        s.adapter: s.reason for s in steps if not s.productive and s.reason
    }

    for pir in plan.pirs:
        if pir.status == "unanswerable":
            continue  # nothing in the registry could answer it; keep that

        satisfied = {
            wanted
            for wanted in pir.answers_attributes
            if any(
                got == wanted or got.startswith(wanted + ".")
                for got in collected
            )
        }
        if satisfied == set(pir.answers_attributes):
            pir.status = "answered"
        elif satisfied:
            missing = sorted(set(pir.answers_attributes) - satisfied)
            pir.status = "partial"
            pir.gap_reason = f"no data collected for {', '.join(missing)}"
        else:
            pir.status = "unanswerable"
            pir.gap_reason = (
                "; ".join(f"{k}: {v}" for k, v in failure_reasons.items())
                or pir.gap_reason
                or "sources ran but produced none of the required attributes"
            )

        pir.fact_ids = _fact_ids_for(engine, company_id, run_id, pir.answers_attributes)


def _fact_ids_for(
    engine: sa.Engine, company_id: str, run_id: str, attributes: frozenset[str]
) -> list[str]:
    """Facts supporting a requirement, so a claim can be drilled into."""
    if not attributes:
        return []
    clauses = [
        sa.or_(
            schema.fact.c.attribute == a,
            schema.fact.c.attribute.startswith(a + ".", autoescape=True),
        )
        for a in sorted(attributes)
    ]
    with engine.connect() as conn:
        rows = conn.execute(
            sa.select(schema.fact.c.id)
            .join(schema.entity, schema.fact.c.entity_id == schema.entity.c.id)
            .where(
                sa.or_(
                    schema.entity.c.id == company_id,
                    schema.entity.c.company_id == company_id,
                ),
                schema.fact.c.run_id == run_id,
                sa.or_(*clauses),
            )
        ).scalars()
        return list(rows)


def _persist_pirs(engine: sa.Engine, run_id: str, pirs: list[PIR]) -> None:
    if not pirs:
        return
    with engine.begin() as conn:
        conn.execute(
            schema.pir.insert(),
            [
                {
                    "id": pir.id,
                    "run_id": run_id,
                    "question": pir.question,
                    "template": pir.template,
                    "answers_attributes": sorted(pir.answers_attributes),
                    "status": pir.status,
                    "answer": pir.answer,
                    "fact_ids": pir.fact_ids,
                    "gap_reason": pir.gap_reason,
                }
                for pir in pirs
            ],
        )
