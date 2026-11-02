"""The database schema, defined once and portable across backends.

Postgres is the deployment target: the ledger's reserve-then-settle needs
``SELECT ... FOR UPDATE`` row locks and the job queue needs ``SKIP LOCKED``,
neither of which SQLite provides. SQLite stays usable for fast unit tests,
which is why the DDL here avoids Postgres-only constructs except through
``with_variant``.

Design notes worth keeping in view while reading:

- ``fact`` is the substrate. A claim is a rendered view of facts, never the
  stored form, because prose cannot be corroborated, diffed, or redacted.
- ``entity.company_id`` scopes company-linked observations; exact email roots
  may stand alone for public research without inventing an organization.
- Enumerations are TEXT plus a CHECK rather than native enums, so adding a
  value is an ordinary migration instead of a type rewrite.

See DATA_MODEL.md for the rationale behind each table.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

metadata = sa.MetaData()


def _json() -> sa.types.TypeEngine:
    """JSON that becomes JSONB on Postgres and plain JSON elsewhere."""
    return sa.JSON().with_variant(postgresql.JSONB, "postgresql")


def _ts(name: str, **kw) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), **kw)


def _money(name: str, **kw) -> sa.Column:
    return sa.Column(name, sa.Numeric(10, 4), **kw)


# Vocabularies. Kept here so the CHECK constraints and the application agree
# on one definition rather than drifting apart.
ENTITY_KINDS = ("company", "domain", "host", "service", "person", "vendor", "email")
CONFIDENCES = ("high", "medium", "low", "unknown")
SENSITIVITIES = ("business", "personal", "restricted")
COLLECTION_MODES = ("third_party_passive", "direct_contact", "active")
AUTHORITY_BASES = ("own_org", "prospect_company", "client_engagement", "public_research")
TIERS = ("A", "B", "C", "D")
SEVERITIES = ("critical", "high", "medium", "low")
RUN_STATUSES = (
    "planning",
    "awaiting_approval",
    "running",
    "complete",
    "stopped",
    "failed",
)
PIR_STATUSES = ("open", "answered", "partial", "unanswerable")
GATE_DECISIONS = ("allowed", "denied", "paused", "settled")
LEDGER_KINDS = (
    "reservation",
    "settlement",
    "fixed_cost",
    "llm_tokens",
    "adjustment",
)
LEDGER_STATES = ("reserved", "settled", "released")
RELATIONSHIP_KINDS = (
    "subdomain_of",
    "resolves_to",
    "runs_service",
    "employee_of",
    "reports_to",
    "owns_budget_for",
    "influences",
    "incumbent_vendor_of",
    "same_as",
)


def _in(column: str, values: tuple[str, ...], name: str) -> sa.CheckConstraint:
    joined = ", ".join(f"'{v}'" for v in values)
    return sa.CheckConstraint(f"{column} IN ({joined})", name=name)


# --------------------------------------------------------------------------
# Direction: who authorized this, and what were we trying to learn
# --------------------------------------------------------------------------

engagement = sa.Table(
    "engagement",
    metadata,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column("authority_basis", sa.String(32), nullable=False),
    sa.Column("client_name", sa.Text),
    # Techniques this engagement permits, e.g. active_scan, username_enum,
    # breach_records. The gate checks an adapter's requires_techniques
    # against this; it is the mechanism that keeps Tier C off prospects.
    sa.Column("permitted_techniques", _json(), nullable=False, server_default="[]"),
    sa.Column("authorized_domains", _json(), nullable=False, server_default="[]"),
    sa.Column("authorized_emails", _json(), nullable=False, server_default="[]"),
    sa.Column("authorized_by", sa.Text, nullable=False),
    sa.Column("document_ref", sa.Text),
    _ts("starts_at", nullable=False),
    _ts("expires_at", nullable=False),
    _ts("created_at", nullable=False),
    _in("authority_basis", AUTHORITY_BASES, "ck_engagement_authority"),
    sa.CheckConstraint(
        "authority_basis <> 'client_engagement' OR client_name IS NOT NULL",
        name="ck_engagement_client_named",
    ),
)

run = sa.Table(
    "run",
    metadata,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column(
        "engagement_id",
        sa.String(32),
        sa.ForeignKey("engagement.id"),
        nullable=False,
    ),
    sa.Column("company_id", sa.String(32), sa.ForeignKey("entity.id"), nullable=False),
    sa.Column("analyst", sa.Text, nullable=False),
    sa.Column("status", sa.String(24), nullable=False),
    # Why the run ended, and what it did not get to. These two columns are
    # what let a briefing say "PIR-2 partial, no org data collected" instead
    # of quietly under-delivering.
    sa.Column("stop_reason", sa.Text),
    sa.Column("skipped", _json(), nullable=False, server_default="[]"),
    sa.Column("max_steps", sa.Integer, nullable=False),
    _money("max_spend_usd", nullable=False),
    sa.Column("max_wall_secs", sa.Integer, nullable=False),
    _ts("started_at", nullable=False),
    _ts("ended_at"),
    _in("status", RUN_STATUSES, "ck_run_status"),
    sa.Index("idx_run_company", "company_id", "started_at"),
)

pir = sa.Table(
    "pir",
    metadata,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column("run_id", sa.String(32), sa.ForeignKey("run.id"), nullable=False),
    sa.Column("question", sa.Text, nullable=False),
    sa.Column("template", sa.Text),
    # The attributes that would answer this requirement. The planner selects
    # adapters whose `produces` intersects this set, which is what makes
    # planning a deterministic table lookup rather than a model call.
    sa.Column("answers_attributes", _json(), nullable=False, server_default="[]"),
    sa.Column("status", sa.String(16), nullable=False, server_default="open"),
    sa.Column("answer", sa.Text),
    sa.Column("fact_ids", _json(), nullable=False, server_default="[]"),
    sa.Column("gap_reason", sa.Text),
    _in("status", PIR_STATUSES, "ck_pir_status"),
    sa.Index("idx_pir_run", "run_id"),
)


# --------------------------------------------------------------------------
# Entities and what we know about them
# --------------------------------------------------------------------------

entity = sa.Table(
    "entity",
    metadata,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column("kind", sa.String(16), nullable=False),
    sa.Column("canonical_name", sa.Text, nullable=False),
    sa.Column("company_id", sa.String(32), sa.ForeignKey("entity.id")),
    sa.Column("aliases", _json(), nullable=False, server_default="[]"),
    sa.Column("confidence", sa.String(8), nullable=False, server_default="unknown"),
    sa.Column("resolved_by", sa.Text),
    sa.Column("merge_history", _json(), nullable=False, server_default="[]"),
    _ts("first_seen_at", nullable=False),
    _ts("last_seen_at", nullable=False),
    _in("kind", ENTITY_KINDS, "ck_entity_kind"),
    _in("confidence", CONFIDENCES, "ck_entity_confidence"),
    # Company-linked kinds retain their research context. An exact email root
    # may stand alone without manufacturing a company or a named person.
    sa.CheckConstraint(
        "kind IN ('company', 'email') OR company_id IS NOT NULL",
        name="ck_entity_company_first",
    ),
    sa.UniqueConstraint(
        "kind", "canonical_name", "company_id", name="uq_entity_identity"
    ),
)

source_record = sa.Table(
    "source_record",
    metadata,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column("run_id", sa.String(32), sa.ForeignKey("run.id"), nullable=False),
    sa.Column("adapter", sa.Text, nullable=False),
    sa.Column("tier", sa.String(1), nullable=False),
    # Always credential-redacted. Collector.record() does this today and the
    # adapter layer keeps doing it; see AUDIT.md P1.
    sa.Column("request_url", sa.Text),
    # Canonical origin, distinct from request_url, so three outlets reprinting
    # one wire story collapse to a single source instead of looking like
    # three-way corroboration.
    sa.Column("origin_url", sa.Text),
    _ts("collected_at", nullable=False),
    sa.Column("collection_mode", sa.String(24), nullable=False),
    sa.Column("raw_payload", sa.LargeBinary),
    sa.Column("raw_sha256", sa.String(64), nullable=False),
    sa.Column("http_status", sa.Integer),
    _ts("retention_expires_at", nullable=False),
    _in("collection_mode", COLLECTION_MODES, "ck_source_mode"),
    _in("tier", TIERS, "ck_source_tier"),
    sa.Index("idx_source_purge", "retention_expires_at"),
    sa.Index("idx_source_run", "run_id"),
)

fact = sa.Table(
    "fact",
    metadata,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column("entity_id", sa.String(32), sa.ForeignKey("entity.id"), nullable=False),
    # Dotted and stable, e.g. dns.a, email.dmarc.policy, tls.not_after.
    # This is the contract between adapters and analysis.
    sa.Column("attribute", sa.Text, nullable=False),
    sa.Column("value", sa.Text, nullable=False),
    sa.Column("value_type", sa.String(16), nullable=False, server_default="str"),
    sa.Column("unit", sa.Text),
    _ts("observed_at", nullable=False),
    sa.Column("run_id", sa.String(32), sa.ForeignKey("run.id"), nullable=False),
    sa.Column(
        "source_record_id",
        sa.String(32),
        sa.ForeignKey("source_record.id"),
        nullable=False,
    ),
    sa.Column("confidence", sa.String(8), nullable=False),
    sa.Column("is_inference", sa.Boolean, nullable=False, server_default=sa.text("false")),
    sa.Column("admiralty_source", sa.String(1), nullable=False),
    sa.Column("admiralty_claim", sa.String(1), nullable=False),
    # The column the exporter and the Tier C panel filter on. Prose claims
    # could not be filtered this way, which is half the reason for this table.
    sa.Column(
        "sensitivity", sa.String(16), nullable=False, server_default="business"
    ),
    _ts("retention_expires_at", nullable=False),
    _in("confidence", CONFIDENCES, "ck_fact_confidence"),
    _in("sensitivity", SENSITIVITIES, "ck_fact_sensitivity"),
    # An inference may never be graded as confirmed or probably-true.
    sa.CheckConstraint(
        "is_inference = FALSE OR admiralty_claim NOT IN ('1', '2')",
        name="ck_fact_inference_not_confirmed",
    ),
    # Keyed on the source record, not the run: two adapters asserting the
    # same (attribute, value) in one run is corroboration and must be
    # storable. This deduplicates a single source repeating itself only.
    sa.UniqueConstraint(
        "entity_id",
        "attribute",
        "value",
        "source_record_id",
        name="uq_fact_per_source",
    ),
    # Lookup by subject, and the corroboration/diff index: same attribute and
    # value seen from a different source record is corroboration.
    sa.Index("idx_fact_subject", "entity_id", "attribute"),
    sa.Index("idx_fact_corroborate", "attribute", "value"),
    sa.Index("idx_fact_purge", "retention_expires_at"),
)

relationship = sa.Table(
    "relationship",
    metadata,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column(
        "source_entity_id", sa.String(32), sa.ForeignKey("entity.id"), nullable=False
    ),
    sa.Column(
        "target_entity_id", sa.String(32), sa.ForeignKey("entity.id"), nullable=False
    ),
    sa.Column("kind", sa.String(24), nullable=False),
    sa.Column("confidence", sa.String(8), nullable=False),
    sa.Column("is_inference", sa.Boolean, nullable=False, server_default=sa.text("false")),
    # How the edge was derived, e.g. 'title-parse-v1'. A power-map edge the
    # analyst cannot interrogate is worse than no edge, so the method is
    # stored alongside the claim.
    sa.Column("inferred_by", sa.Text),
    sa.Column("fact_ids", _json(), nullable=False, server_default="[]"),
    _in("kind", RELATIONSHIP_KINDS, "ck_relationship_kind"),
    _in("confidence", CONFIDENCES, "ck_relationship_confidence"),
    sa.CheckConstraint(
        "is_inference = FALSE OR inferred_by IS NOT NULL",
        name="ck_relationship_inference_shows_method",
    ),
    sa.CheckConstraint(
        "source_entity_id <> target_entity_id", name="ck_relationship_no_self_edge"
    ),
    sa.UniqueConstraint(
        "source_entity_id", "target_entity_id", "kind", name="uq_relationship"
    ),
)


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

exposure = sa.Table(
    "exposure",
    metadata,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column("company_id", sa.String(32), sa.ForeignKey("entity.id"), nullable=False),
    sa.Column("entity_id", sa.String(32), sa.ForeignKey("entity.id")),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("severity", sa.String(8), nullable=False),
    sa.Column("title", sa.Text, nullable=False),
    # The business consequence in plain words, not the technical restatement.
    sa.Column("consequence", sa.Text, nullable=False),
    sa.Column("remediation", sa.Text, nullable=False),
    # Which role owns this problem. The hop that joins the posture half of
    # the tool to the power-map half: the misconfiguration selects the
    # stakeholder to approach.
    sa.Column("stakeholder_function", sa.Text),
    sa.Column("fact_ids", _json(), nullable=False, server_default="[]"),
    _ts("first_seen_at", nullable=False),
    # Set when a later run no longer observes it. Half of the temporal model.
    _ts("resolved_at"),
    _in("severity", SEVERITIES, "ck_exposure_severity"),
    sa.Index("idx_exposure_open", "company_id", "resolved_at"),
)

signal = sa.Table(
    "signal",
    metadata,
    sa.Column("id", sa.String(32), primary_key=True),
    sa.Column("company_id", sa.String(32), sa.ForeignKey("entity.id"), nullable=False),
    sa.Column("kind", sa.Text, nullable=False),
    sa.Column("description", sa.Text, nullable=False),
    sa.Column("why_now", sa.Text, nullable=False),
    sa.Column("score", sa.Numeric(5, 2), nullable=False, server_default="0"),
    sa.Column("confidence", sa.String(8), nullable=False),
    sa.Column(
        "detected_in_run", sa.String(32), sa.ForeignKey("run.id"), nullable=False
    ),
    sa.Column("fact_ids", _json(), nullable=False, server_default="[]"),
    _in("confidence", CONFIDENCES, "ck_signal_confidence"),
    sa.Index("idx_signal_company", "company_id", "score"),
)


# --------------------------------------------------------------------------
# Control: logging, spend, cache
# --------------------------------------------------------------------------

# Append-only by grant: the application role gets INSERT and SELECT, never
# UPDATE or DELETE. Enforced in the Postgres migration, not in Python.
query_log = sa.Table(
    "query_log",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger().with_variant(sa.Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    ),
    _ts("occurred_at", nullable=False),
    sa.Column("analyst", sa.Text, nullable=False),
    sa.Column("run_id", sa.String(32)),
    sa.Column("engagement_id", sa.String(32)),
    sa.Column("authority_basis", sa.String(32), nullable=False),
    sa.Column("adapter", sa.Text, nullable=False),
    sa.Column("tier", sa.String(1), nullable=False),
    sa.Column("target", sa.Text, nullable=False),
    sa.Column("decision", sa.String(16), nullable=False),
    sa.Column("decision_reason", sa.Text),
    _money("estimated_usd"),
    _money("actual_usd"),
    _in("decision", GATE_DECISIONS, "ck_query_log_decision"),
    sa.Index("idx_query_log_time", "occurred_at"),
    sa.Index("idx_query_log_run", "run_id"),
)

budget = sa.Table(
    "budget",
    metadata,
    sa.Column("period", sa.String(7), primary_key=True),
    # '*' is the overall monthly cap; a named adapter is a sub-budget.
    sa.Column("adapter", sa.Text, primary_key=True, server_default="*"),
    sa.Column("cap_usd", sa.Numeric(10, 2), nullable=False),
)

ledger = sa.Table(
    "ledger",
    metadata,
    sa.Column(
        "id",
        sa.BigInteger().with_variant(sa.Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    ),
    sa.Column("period", sa.String(7), nullable=False),
    sa.Column("adapter", sa.Text, nullable=False),
    sa.Column("run_id", sa.String(32)),
    sa.Column("kind", sa.String(16), nullable=False),
    _money("estimated_usd", nullable=False, server_default="0"),
    _money("actual_usd"),
    sa.Column("state", sa.String(16), nullable=False),
    _ts("created_at", nullable=False),
    _ts("settled_at"),
    _in("kind", LEDGER_KINDS, "ck_ledger_kind"),
    _in("state", LEDGER_STATES, "ck_ledger_state"),
    sa.CheckConstraint(
        "state <> 'settled' OR actual_usd IS NOT NULL",
        name="ck_ledger_settled_has_actual",
    ),
    # The query the gate runs under a row lock on the matching budget row.
    sa.Index("idx_ledger_period", "period", "adapter", "state"),
)

cache = sa.Table(
    "cache",
    metadata,
    # sha256(adapter | method | canonical args) — never pay twice in a period.
    sa.Column("key", sa.String(64), primary_key=True),
    sa.Column("adapter", sa.Text, nullable=False),
    sa.Column("payload", sa.LargeBinary, nullable=False),
    _ts("created_at", nullable=False),
    _ts("expires_at", nullable=False),
    sa.Index("idx_cache_expiry", "expires_at"),
)


ALL_TABLES = (
    engagement,
    entity,
    run,
    pir,
    source_record,
    fact,
    relationship,
    exposure,
    signal,
    query_log,
    budget,
    ledger,
    cache,
)
