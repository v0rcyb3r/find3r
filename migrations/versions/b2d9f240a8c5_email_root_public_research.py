"""Exact-email research roots and target scopes, without provider companies.

Revision ID: b2d9f240a8c5
Revises: a1c8e139f7b4
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'b2d9f240a8c5'
down_revision = 'a1c8e139f7b4'
branch_labels = None
depends_on = None


def upgrade():
    json_type = sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')
    with op.batch_alter_table('engagement') as batch:
        batch.add_column(sa.Column('authorized_emails', json_type, nullable=False, server_default='[]'))
        batch.drop_constraint('ck_engagement_authority', type_='check')
        batch.create_check_constraint('ck_engagement_authority',
            "authority_basis IN ('own_org', 'prospect_company', 'client_engagement', 'public_research')")
    with op.batch_alter_table('entity') as batch:
        batch.drop_constraint('ck_entity_kind', type_='check')
        batch.drop_constraint('ck_entity_company_first', type_='check')
        batch.create_check_constraint('ck_entity_kind',
            "kind IN ('company', 'domain', 'host', 'service', 'person', 'vendor', 'email')")
        batch.create_check_constraint('ck_entity_company_first',
            "kind IN ('company', 'email') OR company_id IS NOT NULL")


def downgrade():
    # Do not silently erase email research to force compatibility with the old schema.
    connection = op.get_bind()
    if connection.execute(sa.text("SELECT count(*) FROM entity WHERE kind = 'email'")).scalar():
        raise RuntimeError('Remove email-root research explicitly before downgrading this schema.')
    if connection.execute(sa.text("SELECT count(*) FROM engagement WHERE authority_basis = 'public_research'")).scalar():
        raise RuntimeError('Remove public-research contexts explicitly before downgrading this schema.')
    with op.batch_alter_table('entity') as batch:
        batch.drop_constraint('ck_entity_kind', type_='check')
        batch.drop_constraint('ck_entity_company_first', type_='check')
        batch.create_check_constraint('ck_entity_kind',
            "kind IN ('company', 'domain', 'host', 'service', 'person', 'vendor')")
        batch.create_check_constraint('ck_entity_company_first', "kind = 'company' OR company_id IS NOT NULL")
    with op.batch_alter_table('engagement') as batch:
        batch.drop_column('authorized_emails')
        batch.drop_constraint('ck_engagement_authority', type_='check')
        batch.create_check_constraint('ck_engagement_authority',
            "authority_basis IN ('own_org', 'prospect_company', 'client_engagement')")
