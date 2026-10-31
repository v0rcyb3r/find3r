"""Schema invariant tests.

These assert the constraints that enforce project principles structurally
rather than by convention. If one of these can be violated, the principle is
back to being something a developer has to remember.
"""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import sqlalchemy as sa

from neesha.db import schema

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def db():
    engine = sa.create_engine("sqlite://")

    @sa.event.listens_for(engine, "connect")
    def _fk_on(conn, _rec):
        conn.execute("PRAGMA foreign_keys=ON")

    schema.metadata.create_all(engine)
    with engine.begin() as conn:
        yield conn


def _id() -> str:
    return uuid4().hex


def insert_company(conn, name="acme.com") -> str:
    cid = _id()
    conn.execute(
        schema.entity.insert().values(
            id=cid,
            kind="company",
            canonical_name=name,
            company_id=None,
            confidence="high",
            first_seen_at=NOW,
            last_seen_at=NOW,
        )
    )
    return cid


def insert_engagement(conn, basis="prospect_company", **kw) -> str:
    eid = _id()
    values = dict(
        id=eid,
        authority_basis=basis,
        authorized_by="analyst@vorcyber",
        starts_at=NOW,
        expires_at=NOW + timedelta(days=30),
        created_at=NOW,
    )
    values.update(kw)
    conn.execute(schema.engagement.insert().values(**values))
    return eid


def insert_run(conn, engagement_id, company_id) -> str:
    rid = _id()
    conn.execute(
        schema.run.insert().values(
            id=rid,
            engagement_id=engagement_id,
            company_id=company_id,
            analyst="analyst@vorcyber",
            status="running",
            max_steps=50,
            max_spend_usd=5,
            max_wall_secs=600,
            started_at=NOW,
        )
    )
    return rid


def insert_source(conn, run_id, origin="https://crt.sh/x", adapter="crt.sh") -> str:
    sid = _id()
    conn.execute(
        schema.source_record.insert().values(
            id=sid,
            run_id=run_id,
            adapter=adapter,
            tier="A",
            request_url=origin,
            origin_url=origin,
            collected_at=NOW,
            collection_mode="third_party_passive",
            raw_sha256="0" * 64,
            retention_expires_at=NOW + timedelta(days=30),
        )
    )
    return sid


def insert_fact(conn, entity_id, run_id, source_id, **kw):
    values = dict(
        id=_id(),
        entity_id=entity_id,
        attribute="email.dmarc.policy",
        value="none",
        observed_at=NOW,
        run_id=run_id,
        source_record_id=source_id,
        confidence="high",
        admiralty_source="B",
        admiralty_claim="2",
        retention_expires_at=NOW + timedelta(days=30),
    )
    values.update(kw)
    conn.execute(schema.fact.insert().values(**values))
    return values["id"]


# ---- company-first is structural ----------------------------------------


def test_company_needs_no_parent(db):
    assert insert_company(db)


def test_person_without_a_company_is_unrepresentable(db):
    """The core of 'company-first': no free-standing individual subjects."""
    with pytest.raises(sa.exc.IntegrityError):
        db.execute(
            schema.entity.insert().values(
                id=_id(),
                kind="person",
                canonical_name="A Person",
                company_id=None,
                confidence="medium",
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
        )


def test_person_attached_to_a_company_is_fine(db):
    cid = insert_company(db)
    db.execute(
        schema.entity.insert().values(
            id=_id(),
            kind="person",
            canonical_name="A Person",
            company_id=cid,
            confidence="medium",
            first_seen_at=NOW,
            last_seen_at=NOW,
        )
    )


def test_unknown_entity_kind_is_rejected(db):
    with pytest.raises(sa.exc.IntegrityError):
        db.execute(
            schema.entity.insert().values(
                id=_id(),
                kind="dossier_subject",
                canonical_name="x",
                company_id=None,
                confidence="low",
                first_seen_at=NOW,
                last_seen_at=NOW,
            )
        )


# ---- fact vs inference ---------------------------------------------------


def test_inference_cannot_be_graded_as_confirmed(db):
    """An inference presented as fact is the failure mode principle 2 exists
    to prevent, so the database refuses it."""
    cid = insert_company(db)
    eid = insert_engagement(db)
    rid = insert_run(db, eid, cid)
    sid = insert_source(db, rid)
    for grade in ("1", "2"):
        with pytest.raises(sa.exc.IntegrityError):
            insert_fact(
                db, cid, rid, sid, is_inference=True, admiralty_claim=grade,
                attribute="person.reports_to", value="someone",
            )


def test_inference_graded_possibly_true_is_allowed(db):
    cid = insert_company(db)
    eid = insert_engagement(db)
    rid = insert_run(db, eid, cid)
    sid = insert_source(db, rid)
    assert insert_fact(
        db, cid, rid, sid, is_inference=True, admiralty_claim="3",
        attribute="person.reports_to", value="someone",
    )


def test_unknown_sensitivity_is_rejected(db):
    cid = insert_company(db)
    eid = insert_engagement(db)
    rid = insert_run(db, eid, cid)
    sid = insert_source(db, rid)
    with pytest.raises(sa.exc.IntegrityError):
        insert_fact(db, cid, rid, sid, sensitivity="whatever")


# ---- corroboration, the thing prose claims made impossible ---------------


def test_same_attribute_value_from_two_sources_is_findable(db):
    """AUDIT.md B17: corroboration keyed on (attribute, value) rather than on
    prose. Two adapters wording a claim differently used to make every
    record single-source forever."""
    cid = insert_company(db)
    eid = insert_engagement(db)
    rid = insert_run(db, eid, cid)
    a = insert_source(db, rid, origin="https://crt.sh/x", adapter="crt.sh")
    b = insert_source(db, rid, origin="https://otx.example/y", adapter="otx")

    insert_fact(db, cid, rid, a, attribute="dns.a", value="1.2.3.4")
    insert_fact(db, cid, rid, b, attribute="dns.a", value="1.2.3.4")

    f, s = schema.fact, schema.source_record
    distinct_origins = db.execute(
        sa.select(sa.func.count(sa.distinct(s.c.origin_url)))
        .select_from(f.join(s, f.c.source_record_id == s.c.id))
        .where(f.c.attribute == "dns.a", f.c.value == "1.2.3.4")
    ).scalar()
    assert distinct_origins == 2, "two independent origins corroborate"


def test_one_fact_per_attribute_value_per_source(db):
    cid = insert_company(db)
    eid = insert_engagement(db)
    rid = insert_run(db, eid, cid)
    sid = insert_source(db, rid)
    insert_fact(db, cid, rid, sid, attribute="dns.a", value="1.2.3.4")  # same source
    with pytest.raises(sa.exc.IntegrityError):
        insert_fact(db, cid, rid, sid, attribute="dns.a", value="1.2.3.4")


# ---- power-map edges must show their working ----------------------------


def test_inferred_relationship_must_name_its_method(db):
    cid = insert_company(db)
    p1 = _id()
    p2 = _id()
    for pid, name in ((p1, "Alice Role"), (p2, "Bob Role")):
        db.execute(
            schema.entity.insert().values(
                id=pid, kind="person", canonical_name=name, company_id=cid,
                confidence="medium", first_seen_at=NOW, last_seen_at=NOW,
            )
        )
    with pytest.raises(sa.exc.IntegrityError):
        db.execute(
            schema.relationship.insert().values(
                id=_id(), source_entity_id=p1, target_entity_id=p2,
                kind="reports_to", confidence="low", is_inference=True,
                inferred_by=None,
            )
        )


def test_relationship_rejects_self_edges(db):
    cid = insert_company(db)
    with pytest.raises(sa.exc.IntegrityError):
        db.execute(
            schema.relationship.insert().values(
                id=_id(), source_entity_id=cid, target_entity_id=cid,
                kind="same_as", confidence="high",
            )
        )


# ---- engagement and ledger integrity ------------------------------------


def test_client_engagement_must_name_the_client(db):
    with pytest.raises(sa.exc.IntegrityError):
        insert_engagement(db, basis="client_engagement")


def test_client_engagement_with_a_name_is_fine(db):
    assert insert_engagement(db, basis="client_engagement", client_name="Northwind")


def test_unknown_authority_basis_is_rejected(db):
    with pytest.raises(sa.exc.IntegrityError):
        insert_engagement(db, basis="just_curious")


def test_settled_ledger_row_must_carry_an_actual_amount(db):
    with pytest.raises(sa.exc.IntegrityError):
        db.execute(
            schema.ledger.insert().values(
                period="2026-10", adapter="hunter", kind="settlement",
                estimated_usd=1, actual_usd=None, state="settled",
                created_at=NOW,
            )
        )


def test_reservation_without_an_actual_amount_is_fine(db):
    db.execute(
        schema.ledger.insert().values(
            period="2026-10", adapter="hunter", kind="reservation",
            estimated_usd=1, state="reserved", created_at=NOW,
        )
    )


def test_gate_decision_vocabulary_is_closed(db):
    with pytest.raises(sa.exc.IntegrityError):
        db.execute(
            schema.query_log.insert().values(
                occurred_at=NOW, analyst="a", authority_basis="prospect_company",
                adapter="hunter", tier="B", target="acme.com",
                decision="probably_fine",
            )
        )
