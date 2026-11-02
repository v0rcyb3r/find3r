"""Person names remain labels; explicit identifiers control reuse."""
import sqlalchemy as sa

from neesha.db import schema
from neesha.harness.repository import Repository


def repository(engine):
    company=Repository.ensure_company(engine,'acme.com')
    return Repository(engine,company_id=company,run_id='identity-regression')


def test_same_name_without_identity_key_does_not_merge(engine):
    repo=repository(engine)
    with engine.begin() as conn:
        first=repo.ensure_entity(conn,'person','Alex Smith')
        second=repo.ensure_entity(conn,'person','Alex Smith')
        assert first!=second
        rows=conn.execute(sa.select(schema.entity).where(schema.entity.c.kind=='person')).mappings().all()
    assert len(rows)==2
    assert all(row['aliases']==['Alex Smith'] for row in rows)
    assert all(row['canonical_name'].startswith('unresolved-observation:') for row in rows)


def test_same_name_with_different_explicit_email_keys_does_not_merge(engine):
    repo=repository(engine)
    with engine.begin() as conn:
        first=repo.ensure_entity(conn,'person','Alex Smith',identity_key='email:alex.one@acme.com')
        second=repo.ensure_entity(conn,'person','Alex Smith',identity_key='email:alex.two@acme.com')
    assert first!=second


def test_same_explicit_email_key_reuses_entity_and_preserves_name_alias(engine):
    repo=repository(engine)
    with engine.begin() as conn:
        first=repo.ensure_entity(conn,'person','Alex Smith',identity_key='email:alex@acme.com')
        second=repo.ensure_entity(conn,'person','Alex Smith',identity_key='email:alex@acme.com')
        row=conn.execute(sa.select(schema.entity).where(schema.entity.c.id==first)).mappings().one()
    assert first==second
    assert row['canonical_name']=='email:alex@acme.com'
    assert row['aliases']==['Alex Smith']
    assert row['resolved_by']=='explicit-identifier'


def test_identity_keys_are_company_scoped(engine):
    first_repo=repository(engine)
    second_repo=Repository(engine,Repository.ensure_company(engine,'other.example'),'second-run')
    with engine.begin() as conn:
        first=first_repo.ensure_entity(conn,'person','Alex Smith',identity_key='email:alex@shared.example')
        second=second_repo.ensure_entity(conn,'person','Alex Smith',identity_key='email:alex@shared.example')
    assert first!=second


def test_credential_material_is_not_a_fact():
    import pytest
    from neesha.adapters.base import FactDraft
    with pytest.raises(ValueError, match='Credential'):
        FactDraft(attribute='person.password', value='never-store-this')
    with pytest.raises(ValueError, match='Credential'):
        FactDraft(attribute='person.role', value='password: never-display-this')


def test_redacted_credential_query_is_safe_to_keep_as_provenance():
    from neesha.adapters.base import FactDraft
    fact = FactDraft(attribute='web.archive.url', value='https://example.com/?api_key=REDACTED')
    assert fact.value.endswith('=REDACTED')
