"""The executor: the only thing that calls an adapter.

Nothing else in the system invokes a source. The planner proposes steps, the
gate rules on them, and this runs what the gate approved — which is what
makes "the LLM cannot bypass the gate" true by construction rather than by
discipline. A pivot is a new step and takes the same route.

Order of operations, and why:

1. **Check the cache first**, then estimate. A cache hit costs nothing, so
   its estimate is zero and it does not consume budget. Never paying twice
   for the same lookup in a period is a spec requirement, and this is where
   it is kept.
2. **Still gate a cache hit.** Authority is about whether we may look at this
   target at all, which does not change because we happen to hold a copy.
3. **Reserve, then call, then settle.** A failed call releases its
   reservation rather than leaking it, so a flaky source cannot silently
   consume the month.
4. **Write provenance before facts.** Facts carry a non-null source record
   FK, so there is no window in which a fact exists without its source.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Optional

from neesha.adapters.base import AdapterError, RawResult, Request
from neesha.harness.gate import AdapterSpec, Decision, PolicyGate, RunCaps, RunState
from neesha.harness.repository import Repository
from neesha.ledger.ledger import Ledger, LedgerError

# Outcomes. "collected" and "cached" both produced facts; the rest did not.
COLLECTED = "collected"
CACHED = "cached"
DENIED = "denied"
PAUSED = "paused"
FAILED = "failed"

PRODUCTIVE = (COLLECTED, CACHED)


def spec_of(adapter: Any) -> AdapterSpec:
    """Project an adapter down to what the gate needs to rule on it."""
    return AdapterSpec(
        name=adapter.name,
        tier=adapter.tier,
        collection_mode=adapter.collection_mode,
        requires_techniques=frozenset(getattr(adapter, "requires_techniques", ())),
    )


@dataclass
class StepResult:
    adapter: str
    outcome: str
    reason: str = ""
    facts_written: int = 0
    cost_usd: Decimal = Decimal("0")
    source_record_id: Optional[str] = None
    attributes: list[str] = field(default_factory=list)

    @property
    def productive(self) -> bool:
        return self.outcome in PRODUCTIVE


class Executor:
    def __init__(
        self,
        *,
        gate: PolicyGate,
        ledger: Ledger,
        repository: Repository,
        engagement,
        analyst: str,
        caps: RunCaps,
    ):
        self.gate = gate
        self.ledger = ledger
        self.repo = repository
        self.engagement = engagement
        self.analyst = analyst
        self.caps = caps

    def execute(
        self,
        adapter: Any,
        request: Request,
        state: RunState = RunState(),
        approved: bool = False,
    ) -> StepResult:
        spec = spec_of(adapter)

        # 1. Cache before cost: a hit is free, so it must not be estimated
        #    as though it were a call.
        cache_key = adapter.cache_key(request)
        cached_blob = self.repo.cache_get(cache_key)
        estimate = (
            Decimal("0")
            if cached_blob
            else Decimal(str(adapter.estimate_cost(request).usd))
        )

        # 2. Gate regardless. Holding a copy does not confer authority.
        decision = self.gate.authorize(
            adapter=spec,
            target=request.value,
            engagement=self.engagement,
            analyst=self.analyst,
            caps=self.caps,
            state=state,
            estimated_usd=estimate,
            run_id=self.repo.run_id,
            approved=approved,
        )
        if decision.outcome == DENIED:
            return StepResult(spec.name, DENIED, decision.reason)
        if decision.outcome == PAUSED:
            return StepResult(spec.name, PAUSED, decision.reason)

        if cached_blob:
            raw = RawResult.from_envelope(cached_blob)
            outcome = CACHED
            cost = Decimal("0")
        else:
            raw, failure = self._collect(adapter, request)
            if failure is not None:
                self._release(decision)
                return StepResult(spec.name, FAILED, failure)
            self.repo.cache_put(
                cache_key, spec.name, raw.to_envelope(), adapter.retention_policy()
            )
            outcome = COLLECTED
            cost = self._settle(decision, estimate)

        # 4. Provenance first, then the facts that depend on it.
        source_record_id = self.repo.write_source_record(
            adapter=spec.name,
            tier=spec.tier,
            collection_mode=spec.collection_mode,
            raw=raw,
            retention=adapter.retention_policy(),
        )

        try:
            drafts = adapter.parse(raw, request)
        except AdapterError as exc:
            # The call succeeded and was paid for; only parsing failed. The
            # source record stays, so the raw payload is available to
            # re-parse once the parser is fixed.
            return StepResult(
                spec.name,
                FAILED,
                f"parse failed: {exc}",
                cost_usd=cost,
                source_record_id=source_record_id,
            )

        written = self.repo.write_facts(
            drafts,
            source_record_id=source_record_id,
            source_type=getattr(adapter, "source_type", "osint"),
            subject_name=request.value,
            retention=adapter.retention_policy(),
        )
        return StepResult(
            adapter=spec.name,
            outcome=outcome,
            reason="" if outcome == COLLECTED else "served from cache",
            facts_written=len(written),
            cost_usd=cost,
            source_record_id=source_record_id,
            attributes=sorted({f.attribute for f in written}),
        )

    # ---- internals -------------------------------------------------------

    @staticmethod
    def _collect(adapter: Any, request: Request) -> tuple[Any, Optional[str]]:
        """Run search+fetch, converting adapter failures into a reason string.

        A failed collection is an absence of fact, never a fact about
        absence: nothing is written, and the caller records a gap.
        """
        try:
            references = adapter.search(request)
        except AdapterError as exc:
            return None, f"search failed: {exc}"
        if not references:
            return None, "no results"
        try:
            return adapter.fetch(references[0]), None
        except AdapterError as exc:
            return None, f"fetch failed: {exc}"

    def _settle(self, decision: Decision, estimate: Decimal) -> Decimal:
        """Settle a reservation at the actual cost.

        Until providers' usage endpoints are wired in, the estimate is the
        best available actual. Nightly reconciliation against provider usage
        is what will correct the drift.
        """
        if decision.reservation is None:
            return Decimal("0")
        try:
            self.ledger.settle(decision.reservation.id, estimate)
        except LedgerError:
            return estimate
        return estimate

    def _release(self, decision: Decision) -> None:
        if decision.reservation is None:
            return
        try:
            self.ledger.release(decision.reservation.id)
        except LedgerError:
            pass


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
