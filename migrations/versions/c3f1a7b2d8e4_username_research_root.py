"""Username research roots for account-enumeration subjects.

A username may stand alone as a research root (like an exact email), without
manufacturing a company or named person.

Revision ID: c3f1a7b2d8e4
Revises: b2d9f240a8c5
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'c3f1a7b2d8e4'
down_revision = 'b2d9f240a8c5'
branch_labels = None
depends_on = None


def upgrade():
    json_type = sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')
    with op.batch_alter_table('engagement') as batch:
        batch.add_column(sa.Column('authorized_usernames', json_type, nullable=False, server_default='[]'))
    with op.batch_alter_table('entity') as batch:
        batch.drop_constraint('ck_entity_kind', type_='check')
        batch.drop_constraint('ck_entity_company_first', type_='check')
        batch.create_check_constraint('ck_entity_kind',
            "kind IN ('company', 'domain', 'host', 'service', 'person', 'vendor', 'email', 'username')")
        batch.create_check_constraint('ck_entity_company_first',
            "kind IN ('company', 'email', 'username') OR company_id IS NOT NULL")


def downgrade():
    connection = op.get_bind()
    if connection.execute(sa.text("SELECT count(*) FROM entity WHERE kind = 'username'")).scalar():
        raise RuntimeError('Remove username-root research explicitly before downgrading this schema.')
    with op.batch_alter_table('entity') as batch:
        batch.drop_constraint('ck_entity_kind', type_='check')
        batch.drop_constraint('ck_entity_company_first', type_='check')
        batch.create_check_constraint('ck_entity_kind',
            "kind IN ('company', 'domain', 'host', 'service', 'person', 'vendor', 'email')")
        batch.create_check_constraint('ck_entity_company_first',
            "kind IN ('company', 'email') OR company_id IS NOT NULL")
    with op.batch_alter_table('engagement') as batch:
        batch.drop_column('authorized_usernames')
