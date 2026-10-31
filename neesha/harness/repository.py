"""Persistence for the harness: entities, source records, facts, cache.

Deliberately thin. There is no ORM and no identity map, because the write
pattern is narrow: a run resolves a company once, then appends source
records and facts. Reads during analysis are queries, not object graphs.

Two rules are enforced here rather than left to callers:

- Every non-company entity is attached to a company. The schema has the
  CHECK; this makes it impossible to reach by accident, because the company
  id is a constructor argument rather than a per-call option.
- Facts are graded by the guardrail tables, never by the adapter that
  produced them. A collector must not be able to certify its own output.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional
from uuid import uuid4

import sqlalchemy as sa

from neesha.adapters.base import FactDraft, RawResult
from neesha.db import schema
from neesha.guardrail.admiralty import grade_claim, grade_source

# source_type names used by the Admiralty tables, keyed by adapter tier and
# intent. Adapters declare a source_type so grading stays table-driven.
DEFAULT_SOURCE_TYPE = "osint"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _id() -> str:
    return uuid4().hex


@dataclass(frozen=True)
class WrittenFact:
    id: str
    entity_id: str
    attribute: str
    value: str
    confidence: str
    admiralty: str
    is_inference: bool


class Repository:
    def __init__(self, engine: sa.Engine, company_id: str, run_id: str):
        self.engine = engine
        self.company_id = company_id
        self.run_id = run_id

    # ---- entities --------------------------------------------------------

    @classmethod
    def ensure_company(cls, engine: sa.Engine, name: str) -> str:
        """Find or create the company a run is about."""
        canonical = name.strip().lower().rstrip(".")
        with engine.begin() as conn:
            existing = conn.execute(
                sa.select(schema.entity.c.id).where(
                    schema.entity.c.kind == "company",
                    schema.entity.c.canonical_name == canonical,
                    schema.entity.c.company_id.is_(None),
                )
            ).scalar()
            if existing:
                return existing
            new_id = _id()
            now = _now()
            conn.execute(
                schema.entity.insert().values(
                    id=new_id,
                    kind="company",
                    canonical_name=canonical,
                    company_id=None,
                    confidence="high",
                    resolved_by="run-seed",
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            return new_id

    def ensure_entity(self, conn, kind: str, name: str) -> str:
        """Find or create an entity, always under this run's company.

        ``last_seen_at`` is bumped on every sighting, which is what lets a
        later run tell a still-present asset from a disappeared one.
        """
        canonical = name.strip().lower().rstrip(".")
        if kind == "company":
            return self.company_id

        existing = conn.execute(
            sa.select(schema.entity.c.id).where(
                schema.entity.c.kind == kind,
                schema.entity.c.canonical_name == canonical,
                schema.entity.c.company_id == self.company_id,
            )
        ).scalar()
        now = _now()
        if existing:
            conn.execute(
                schema.entity.update()
                .where(schema.entity.c.id == existing)
                .values(last_seen_at=now)
            )
            return existing

        new_id = _id()
        conn.execute(
            schema.entity.insert().values(
                id=new_id,
                kind=kind,
                canonical_name=canonical,
                company_id=self.company_id,
                confidence="medium",
                resolved_by="adapter",
                first_seen_at=now,
                last_seen_at=now,
            )
        )
        return new_id

    # ---- source records and facts ---------------------------------------

    def write_source_record(
        self,
        *,
        adapter: str,
        tier: str,
        collection_mode: str,
        raw: RawResult,
        retention: timedelta,
        store_payload: bool = True,
        collected_at: Optional[datetime] = None,
    ) -> str:
        """Record the provenance of one collection, and optionally its body.

        ``request_url`` arrives already redacted — adapters are responsible
        for never putting a credential in it, and AUDIT.md P1 is why.
        """
        record_id = _id()
        with self.engine.begin() as conn:
            conn.execute(
                schema.source_record.insert().values(
                    id=record_id,
                    run_id=self.run_id,
                    adapter=adapter,
                    tier=tier,
                    request_url=raw.request_url,
                    origin_url=raw.origin_url or raw.request_url,
                    collected_at=collected_at or raw.collected_at or _now(),
                    collection_mode=collection_mode,
                    raw_payload=raw.payload if store_payload else None,
                    raw_sha256=raw.sha256,
                    http_status=raw.http_status,
                    retention_expires_at=_now() + retention,
                )
            )
        return record_id

    def write_facts(
        self,
        drafts: Iterable[FactDraft],
        *,
        source_record_id: str,
        source_type: str,
        subject_name: str,
        retention: timedelta,
    ) -> list[WrittenFact]:
        """Persist fact drafts, grading them from the Admiralty tables.

        Corroboration is checked against what is already stored: if another
        source record already asserts this exact (attribute, value), both are
        corroborated and the claim grade improves a notch. This is the
        mechanism the old prose-keyed guardrail could not implement — see
        AUDIT.md B17.
        """
        written: list[WrittenFact] = []
        source_grade = grade_source(source_type)
        now = _now()
        expires = now + retention

        with self.engine.begin() as conn:
            for draft in drafts:
                entity_id = self.ensure_entity(
                    conn, draft.entity_kind, draft.entity_name or subject_name
                )

                corroborated = self._has_independent_support(
                    conn, draft.attribute, draft.value, source_record_id
                )
                claim_grade = grade_claim(
                    source_type,
                    is_inference=draft.is_inference,
                    corroborated=corroborated,
                )
                confidence = self._confidence_for(
                    source_type, corroborated, draft.is_inference
                )

                fact_id = _id()
                try:
                    conn.execute(
                        schema.fact.insert().values(
                            id=fact_id,
                            entity_id=entity_id,
                            attribute=draft.attribute,
                            value=draft.value,
                            value_type=draft.value_type,
                            unit=draft.unit,
                            observed_at=now,
                            run_id=self.run_id,
                            source_record_id=source_record_id,
                            confidence=confidence,
                            is_inference=draft.is_inference,
                            admiralty_source=source_grade.value,
                            admiralty_claim=str(claim_grade),
                            sensitivity=draft.sensitivity,
                            retention_expires_at=expires,
                        )
                    )
                except sa.exc.IntegrityError:
                    # This source already asserted this exact fact. Not an
                    # error: adapters legitimately repeat themselves across
                    # paginated results.
                    continue

                written.append(
                    WrittenFact(
                        id=fact_id,
                        entity_id=entity_id,
                        attribute=draft.attribute,
                        value=draft.value,
                        confidence=confidence,
                        admiralty=f"{source_grade.value}{claim_grade}",
                        is_inference=draft.is_inference,
                    )
                )
        return written

    @staticmethod
    def _has_independent_support(
        conn, attribute: str, value: str, source_record_id: str
    ) -> bool:
        """True if a different origin already asserts this attribute+value.

        Keyed on the source record's canonical origin, not on the fetch URL,
        so three outlets reprinting one wire story do not look like
        three-way agreement.
        """
        this_origin = conn.execute(
            sa.select(schema.source_record.c.origin_url).where(
                schema.source_record.c.id == source_record_id
            )
        ).scalar()
        others = conn.execute(
            sa.select(sa.func.count(sa.distinct(schema.source_record.c.origin_url)))
            .select_from(
                schema.fact.join(
                    schema.source_record,
                    schema.fact.c.source_record_id == schema.source_record.c.id,
                )
            )
            .where(
                schema.fact.c.attribute == attribute,
                schema.fact.c.value == value,
                schema.source_record.c.origin_url.is_not(None),
                schema.source_record.c.origin_url != this_origin,
            )
        ).scalar()
        return bool(others)

    @staticmethod
    def _confidence_for(
        source_type: str, corroborated: bool, is_inference: bool
    ) -> str:
        """Apply the confidence ceilings.

        A single uncorroborated secondary source is capped at medium;
        corroboration lifts the cap. Direct observations have no ceiling.
        Inferences never reach high.
        """
        from neesha.guardrail.engine import CONFIDENCE_CEILINGS

        ceiling = CONFIDENCE_CEILINGS.get(source_type)
        if is_inference:
            return "medium" if corroborated else "low"
        if ceiling is not None and not corroborated:
            return ceiling.value
        return "high"

    # ---- cache -----------------------------------------------------------

    def cache_get(self, key: str) -> Optional[bytes]:
        with self.engine.connect() as conn:
            row = conn.execute(
                sa.select(schema.cache.c.payload, schema.cache.c.expires_at).where(
                    schema.cache.c.key == key
                )
            ).first()
        if row is None:
            return None
        expires = row.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= _now():
            return None
        return row.payload

    def cache_put(self, key: str, adapter: str, payload: bytes, ttl: timedelta) -> None:
        now = _now()
        with self.engine.begin() as conn:
            conn.execute(schema.cache.delete().where(schema.cache.c.key == key))
            conn.execute(
                schema.cache.insert().values(
                    key=key,
                    adapter=adapter,
                    payload=payload,
                    created_at=now,
                    expires_at=now + ttl,
                )
            )

    # ---- retention -------------------------------------------------------

    def purge_expired(self, now: Optional[datetime] = None) -> dict[str, int]:
        """Delete everything past its retention date.

        Not housekeeping: Hunter's terms make us an independent GDPR
        controller for retrieved personal data, so this is the control that
        discharges that duty. See DATA_MODEL.md section 1.
        """
        cutoff = now or _now()
        counts: dict[str, int] = {}
        with self.engine.begin() as conn:
            counts["fact"] = conn.execute(
                schema.fact.delete().where(
                    schema.fact.c.retention_expires_at <= cutoff
                )
            ).rowcount
            counts["source_record"] = conn.execute(
                schema.source_record.delete().where(
                    schema.source_record.c.retention_expires_at <= cutoff
                )
            ).rowcount
            counts["cache"] = conn.execute(
                schema.cache.delete().where(schema.cache.c.expires_at <= cutoff)
            ).rowcount
        return counts
